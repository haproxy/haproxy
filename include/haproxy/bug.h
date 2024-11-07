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

#include <stddef.h>
#include <sys/types.h>
#include <haproxy/atomic.h>
#include <haproxy/compiler.h>

/* quick debugging hack, should really be removed ASAP */
#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

#define DUMP_TRACE() do { extern void ha_backtrace_to_stderr(void); ha_backtrace_to_stderr(); } while (0)

/* First, let's try to handle some arch-specific crashing methods. We prefer
 * the macro to the function because when opening the core, the debugger will
 * directly show the calling point (e.g. the BUG_ON() condition) based on the
 * line number, while the function will create new line numbers. But the
 * function is needed e.g. if some pragmas are needed.
 */

#if defined(__i386__) || defined(__x86_64__)
#define ha_crash_now() do {						\
		/* ud2 opcode: 2 bytes, raises illegal instruction */	\
		__asm__ volatile(".byte 0x0f,0x0b\n");			\
		DO_NOT_FOLD();						\
		my_unreachable();					\
	} while (0)

#elif defined(__aarch64__)
#define ha_crash_now() do {						\
		/* udf#imm16: 4 bytes (), raises illegal instruction */	\
		__asm__ volatile(".byte 0x00,0x00,0x00,0x00\n");	\
		DO_NOT_FOLD();						\
		my_unreachable();					\
	} while (0)

#else // not x86

/* generic implementation, causes a segfault */
static inline __attribute((always_inline)) void ha_crash_now(void)
{
#if __GNUC_PREREQ__(5, 0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#if __GNUC_PREREQ__(6, 0)
#pragma GCC diagnostic ignored "-Wnull-dereference"
#endif
#endif
	*(volatile char *)1 = 0;
#if __GNUC_PREREQ__(5, 0)
#pragma GCC diagnostic pop
#endif
	DO_NOT_FOLD();
	my_unreachable();
}

#endif // end of arch-specific ha_crash_now() definitions


/* ABORT_NOW() usually takes no argument and will cause the program to abort
 * exactly where it is. We prefer to emit an invalid instruction to preserve
 * all registers, but it may fall back to a regular abort depending on the
 * platform. An optional argument can be a message string that will cause
 * the emission of a message saying "ABORT at" followed by the file and line
 * number then that message followed by a final line feed. This can be helpful
 * in situations where the core cannot be retrieved for example. However it
 * will definitely cause the loss of some registers, so should be avoided when
 * not strictly necessary.
 */
#define ABORT_NOW(...)							\
	_ABORT_NOW(__FILE__, __LINE__, __VA_ARGS__)

#define _ABORT_NOW(file, line, ...)					\
	__ABORT_NOW(file, line, __VA_ARGS__)

#ifdef DEBUG_USE_ABORT
/* abort() is better recognized by code analysis tools */

/* abort() is generally tagged noreturn, so there's no 100% safe way to prevent
 * the compiler from doing a tail-merge here. Tests show that stopping folding
 * just before calling abort() does work in practice at -O2, increasing the
 * number of abort() calls in h3.o from 18 to 26, probably because there's no
 * more savings to be made by replacing a call with a jump. However, as -Os it
 * drops to 5 regardless of the build option. In order to help here, instead we
 * wrap abort() into another function, with the line number stored into a local
 * variable on the stack and we pretend to use it, so that unwinding the stack
 * from abort() will reveal its value even if the call was folded.
 */
static __attribute__((noinline,noreturn,unused)) void abort_with_line(uint line)
{
	DISGUISE(&line);
	abort();
}

#define __ABORT_NOW(file, line, ...) do {				\
		extern ssize_t write(int, const void *, size_t);	\
		extern size_t strlen(const char *s);			\
		const char *msg;					\
		if (sizeof("" __VA_ARGS__) > 1)				\
			complain(NULL, "\nABORT at " file ":" #line ": " __VA_ARGS__ "\n", 1); \
		DUMP_TRACE();						\
		msg = "\n"						\
		      "Hint: when reporting this bug to developers, please check if a core file was\n" \
		      "      produced, open it with 'gdb', issue 'bt' to produce a backtrace for the\n" \
		      "      current thread only, then join it with the bug report.\n"; \
		DISGUISE(write(2, msg, strlen(msg)));			\
		abort_with_line(__LINE__);				\
	} while (0)
#else
/* More efficient than abort() because it does not mangle the
 * stack and stops at the exact location we need.
 */
#define __ABORT_NOW(file, line, ...) do {				\
		extern ssize_t write(int, const void *, size_t);	\
		extern size_t strlen(const char *s);			\
		const char *msg;					\
		if (sizeof("" __VA_ARGS__) > 1)				\
			complain(NULL, "\nABORT at " file ":" #line ": " __VA_ARGS__ "\n", 1); \
		DUMP_TRACE();						\
		msg = "\n"						\
		      "Hint: when reporting this bug to developers, please check if a core file was\n" \
		      "      produced, open it with 'gdb', issue 'bt' to produce a backtrace for the\n" \
		      "      current thread only, then join it with the bug report.\n"; \
		DISGUISE(write(2, msg, strlen(msg)));			\
		ha_crash_now();						\
	} while (0)
#endif

/* Counting the number of matches on a given BUG_ON()/WARN_ON()/CHECK_IF()/
 * COUNT_IF() invocation requires a special section ("dbg_cnt") hence a modern
 * linker.
 */
#if !defined(USE_OBSOLETE_LINKER)

/* type of checks that can be verified. We cannot really distinguish between
 * BUG/WARN/CHECK_IF as they all pass through __BUG_ON() at a different level,
 * but there's at least a difference between __BUG_ON() and __BUG_ON_ONCE()
 * (and of course COUNT_IF).
 */
enum debug_counter_type {
	DBG_BUG,
	DBG_BUG_ONCE,
	DBG_COUNT_IF,
	DBG_GLITCH,
	DBG_COUNTER_TYPES // must be last
};

/* this is the struct that we store in section "dbg_cnt". Better keep it
 * well aligned.
 */
struct debug_count {
	const char *file;
	const char *func;
	const char *desc;
	uint16_t    line;
	uint8_t     type;
	/* one-byte hole here */
	uint32_t   count;
};

/* Declare a section for condition counters. The start and stop pointers are
 * set by the linker itself, which is why they're declared extern here. The
 * weak attribute is used so that we declare them ourselves if the section is
 * empty. The corresponding section must contain exclusively struct debug_count
 * to make sure each location may safely be visited by incrementing a pointer.
 */
extern __attribute__((__weak__)) struct debug_count __start_dbg_cnt HA_SECTION_START("dbg_cnt");
extern __attribute__((__weak__)) struct debug_count __stop_dbg_cnt  HA_SECTION_STOP("dbg_cnt");

/* This macro adds a pass counter at the line where it's declared. It can be
 * used by the various BUG_ON, COUNT_IF etc flavors. The condition is only
 * passed for the sake of being turned into a string; the caller is expected
 * to have already verified it.
 */
#define __DBG_COUNT(_cond, _file, _line, _type, ...) do {			\
		static struct debug_count __dbg_cnt_##_line HA_SECTION("dbg_cnt") \
		__attribute__((__used__,__aligned__(sizeof(void*)))) = { 	\
			.file = _file,						\
			.func = __func__,					\
			.line = _line,						\
			.type = _type,						\
			.desc = (sizeof("" #_cond) > 1) ?			\
				  (sizeof("" __VA_ARGS__) > 1) ?		\
				  "\"" #_cond "\" [" __VA_ARGS__ "]" :		\
				  "\"" #_cond "\"" :				\
				"" __VA_ARGS__,					\
			.count = 0,						\
		};								\
		HA_WEAK(__start_dbg_cnt);					\
		HA_WEAK(__stop_dbg_cnt);					\
		_HA_ATOMIC_INC(&__dbg_cnt_##_line.count);			\
	} while (0)

/* Core of the COUNT_IF() macro, checks the condition and counts one hit if
 * true.
 */
#define _COUNT_IF(cond, file, line, ...)					\
	(unlikely(cond) ? ({							\
		__DBG_COUNT(cond, file, line, DBG_COUNT_IF, __VA_ARGS__);	\
		1; /* let's return the true condition */			\
	}) : 0)

/* DEBUG_GLITCHES enables counting the number of glitches per line of code. The
 * condition is empty (nothing to write there), except maybe __VA_ARGS at the
 * end.
 */
# if !defined(DEBUG_GLITCHES)
#  define _COUNT_GLITCH(file, line, ...) do { } while (0)
# else
#  define _COUNT_GLITCH(file, line, ...) do {						\
		__DBG_COUNT(, file, line, DBG_GLITCH, __VA_ARGS__); 	\
	} while (0)
#  endif

#else /* USE_OBSOLETE_LINKER not defined below  */
# define __DBG_COUNT(cond, file, line, type, ...) do { } while (0)
# define _COUNT_IF(cond, file, line, ...) DISGUISE(cond)
# define _COUNT_GLITCH(file, line, ...) do { } while (0)
#endif

/* reports a glitch for current file and line, optionally with an explanation */
#define COUNT_GLITCH(...) _COUNT_GLITCH(__FILE__, __LINE__, __VA_ARGS__)

/* This is the generic low-level macro dealing with conditional warnings and
 * bugs. The caller decides whether to crash or not and what prefix and suffix
 * to pass. The macro returns the boolean value of the condition as an int for
 * the case where it wouldn't die. The <crash> flag is made of:
 *  - crash & 1: crash yes/no;
 *  - crash & 2: taint as bug instead of warn
 * The optional argument must be a single constant string that will be appended
 * on a second line after the condition message, to give a bit more context
 * about the problem.
 */
#define _BUG_ON(cond, file, line, crash, pfx, sfx, ...)				\
	(void)(unlikely(cond) ? ({						\
		__DBG_COUNT(cond, file, line, DBG_BUG, __VA_ARGS__); 		\
		__BUG_ON(cond, file, line, crash, pfx, sfx, __VA_ARGS__);	\
		1; /* let's return the true condition */			\
	}) : 0)

#define __BUG_ON(cond, file, line, crash, pfx, sfx, ...) do {		\
		const char *msg;					\
		if (sizeof("" __VA_ARGS__) > 1)				\
			msg ="\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n" __VA_ARGS__ "\n"; \
		else							\
			msg = "\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n"; \
		complain(NULL, msg, crash);				\
		if (crash & 1)						\
			ABORT_NOW();					\
		else							\
			DUMP_TRACE();					\
	} while (0)

/* This one is equivalent except that it only emits the message once by
 * maintaining a static counter. This may be used with warnings to detect
 * certain unexpected conditions in field. Later on, in cores it will be
 * possible to verify these counters.
 */
#define _BUG_ON_ONCE(cond, file, line, crash, pfx, sfx, ...)			\
	(void)(unlikely(cond) ? ({						\
		__DBG_COUNT(cond, file, line, DBG_BUG_ONCE, __VA_ARGS__); 	\
		__BUG_ON_ONCE(cond, file, line, crash, pfx, sfx, __VA_ARGS__);	\
		1; /* let's return the true condition */			\
	}) : 0)

#define __BUG_ON_ONCE(cond, file, line, crash, pfx, sfx, ...) do {	\
		static int __match_count_##line;			\
		const char *msg;					\
		if (sizeof("" __VA_ARGS__) > 1)				\
			msg ="\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n" __VA_ARGS__ "\n"; \
		else							\
			msg = "\n" pfx "condition \"" #cond "\" matched at " file ":" #line "" sfx "\n"; \
		complain(&__match_count_##line, msg, crash);		\
		if (crash & 1)						\
			ABORT_NOW();					\
		else							\
			DUMP_TRACE();					\
	} while (0)


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
#if defined(DEBUG_STRICT) && (DEBUG_STRICT > 0)
# if defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION < 1)
/* Lowest level: BUG_ON() warns, WARN_ON() warns, CHECK_IF() warns */
#  define BUG_ON(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 2, "WARNING: bug ",   " (not crashing but process is untrusted now, please report to developers)", __VA_ARGS__)
#  define WARN_ON(cond, ...)  _BUG_ON     (cond, __FILE__, __LINE__, 0, "WARNING: warn ",  " (please report to developers)", __VA_ARGS__)
#  define CHECK_IF(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)", __VA_ARGS__)
#  define COUNT_IF(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# elif !defined(DEBUG_STRICT_ACTION) || (DEBUG_STRICT_ACTION == 1)
/* default level: BUG_ON() crashes, WARN_ON() warns, CHECK_IF() warns */
#  define BUG_ON(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "", __VA_ARGS__)
#  define WARN_ON(cond, ...)  _BUG_ON     (cond, __FILE__, __LINE__, 0, "WARNING: warn ",  " (please report to developers)", __VA_ARGS__)
#  define CHECK_IF(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)", __VA_ARGS__)
#  define COUNT_IF(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION == 2)
/* Stricter level: BUG_ON() crashes, WARN_ON() crashes, CHECK_IF() warns */
#  define BUG_ON(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "", __VA_ARGS__)
#  define WARN_ON(cond, ...)  _BUG_ON     (cond, __FILE__, __LINE__, 1, "FATAL: warn ",    "", __VA_ARGS__)
#  define CHECK_IF(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)", __VA_ARGS__)
#  define COUNT_IF(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION >= 3)
/* Developer/CI level: BUG_ON() crashes, WARN_ON() crashes, CHECK_IF() crashes */
#  define BUG_ON(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "", __VA_ARGS__)
#  define WARN_ON(cond, ...)  _BUG_ON     (cond, __FILE__, __LINE__, 1, "FATAL: warn ",    "", __VA_ARGS__)
#  define CHECK_IF(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 1, "FATAL: check ",   "", __VA_ARGS__)
#  define COUNT_IF(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# endif
#else
/* We want BUG_ON() to evaluate the expression sufficiently for next lines
 * of codes not to complain about suspicious dereferences for example.
 * GCC-11 tends to fail to validate that in combined expressions such as
 * "BUG_ON(!a || !b)", but it works fine when using a temporary assignment
 * like below, without hurting the generated code.
 */
#  define BUG_ON(cond, ...)   ({ typeof(cond) __cond = (cond); ASSUME(!__cond); })
#  define WARN_ON(cond, ...)  do { (void)sizeof(cond); } while (0)
#  define CHECK_IF(cond, ...) do { (void)sizeof(cond); } while (0)
#  define COUNT_IF(cond, ...) DISGUISE(cond)
#endif

/* These macros are only for hot paths and remain disabled unless DEBUG_STRICT is 2 or above.
 * Only developers/CI should use these levels as they may significantly impact performance by
 * enabling checks in sensitive areas.
 */
#if defined(DEBUG_STRICT) && (DEBUG_STRICT > 1)
# if defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION < 1)
/* Lowest level: BUG_ON() warns, CHECK_IF() warns */
#  define BUG_ON_HOT(cond, ...)   _BUG_ON_ONCE(cond, __FILE__, __LINE__, 2, "WARNING: bug ",   " (not crashing but process is untrusted now, please report to developers)", __VA_ARGS__)
#  define CHECK_IF_HOT(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)", __VA_ARGS__)
#  define COUNT_IF_HOT(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# elif !defined(DEBUG_STRICT_ACTION) || (DEBUG_STRICT_ACTION < 3)
/* default level: BUG_ON() crashes, CHECK_IF() warns */
#  define BUG_ON_HOT(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "", __VA_ARGS__)
#  define CHECK_IF_HOT(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 0, "WARNING: check ", " (please report to developers)", __VA_ARGS__)
#  define COUNT_IF_HOT(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# elif defined(DEBUG_STRICT_ACTION) && (DEBUG_STRICT_ACTION >= 3)
/* Developer/CI level: BUG_ON() crashes, CHECK_IF() crashes */
#  define BUG_ON_HOT(cond, ...)   _BUG_ON     (cond, __FILE__, __LINE__, 3, "FATAL: bug ",     "", __VA_ARGS__)
#  define CHECK_IF_HOT(cond, ...) _BUG_ON_ONCE(cond, __FILE__, __LINE__, 1, "FATAL: check ",   "", __VA_ARGS__)
#  define COUNT_IF_HOT(cond, ...) _COUNT_IF   (cond, __FILE__, __LINE__, __VA_ARGS__)
# endif
#else
/* Contrary to BUG_ON(), we do *NOT* want BUG_ON_HOT() to evaluate the
 * expression unless explicitly enabled, since it is located in hot code paths.
 * We just validate that the expression results in a valid type.
 */
#  define BUG_ON_HOT(cond, ...)   do { (void)sizeof(cond) ; } while (0)
#  define CHECK_IF_HOT(cond, ...) do { (void)sizeof(cond) ; } while (0)
#  define COUNT_IF_HOT(cond, ...) DISGUISE(cond)
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

/* describes a call place in the code, for example for tracing memory
 * allocations or task wakeups. These must be declared static const.
 */
struct ha_caller {
	const char *func;  // function name
	const char *file;  // file name
	uint16_t line;     // line number
	uint8_t what;      // description of the call, usage specific
	uint8_t arg8;      // optional argument, usage specific
	uint32_t arg32;    // optional argument, usage specific
};

#define MK_CALLER(_what, _arg8, _arg32)					\
	({ static const struct ha_caller _ = {				\
		.func = __func__, .file = __FILE__, .line = __LINE__,	\
		.what = _what, .arg8 = _arg8, .arg32 = _arg32 };	\
		&_; })

/* handle 'tainted' status */
enum tainted_flags {
	TAINTED_CONFIG_EXP_KW_DECLARED = 0x00000001,
	TAINTED_ACTION_EXP_EXECUTED    = 0x00000002,
	TAINTED_CLI_EXPERT_MODE        = 0x00000004,
	TAINTED_CLI_EXPERIMENTAL_MODE  = 0x00000008,
	TAINTED_WARN                   = 0x00000010, /* a WARN_ON triggered */
	TAINTED_BUG                    = 0x00000020, /* a BUG_ON triggered */
	TAINTED_SHARED_LIBS            = 0x00000040, /* a shared library was loaded */
	TAINTED_REDEFINITION           = 0x00000080, /* symbol redefinition detected */
	TAINTED_REPLACED_MEM_ALLOCATOR = 0x00000100, /* memory allocator was replaced using LD_PRELOAD */
	TAINTED_PANIC                  = 0x00000200, /* a panic dump has started */
	TAINTED_LUA_STUCK              = 0x00000400, /* stuck in a Lua context */
	TAINTED_LUA_STUCK_SHARED       = 0x00000800, /* stuck in a shared Lua context */
	TAINTED_MEM_TRIMMING_STUCK     = 0x00001000, /* stuck while trimming memory */
	TAINTED_WARN_BLOCKED_TRAFFIC   = 0x00002000, /* emitted a warning about blocked traffic */
};

/* this is a bit field made of TAINTED_*, and is declared in haproxy.c */
extern unsigned int tainted;

void complain(int *counter, const char *msg, int taint);

static inline unsigned int mark_tainted(const enum tainted_flags flag)
{
	return HA_ATOMIC_FETCH_OR(&tainted, flag);
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
	MEM_STATS_TYPE_P_ALLOC,
	MEM_STATS_TYPE_P_FREE,
};

struct mem_stats {
	size_t calls;
	size_t size;
	struct ha_caller caller;
	const void *extra; // extra info specific to this call (e.g. pool ptr)
} __attribute__((aligned(sizeof(void*))));

#undef calloc
#define calloc(x,y)  ({							\
	size_t __x = (x); size_t __y = (y);				\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_CALLOC,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __x * __y);				\
	calloc(__x,__y);						\
})

/* note: we can't redefine free() because we have a few variables and struct
 * members called like this. This one may be used before a call to free(),
 * and when known, the size should be indicated, otherwise pass zero. The
 * pointer is used to know whether the call should be accounted for (null is
 * ignored).
 */
#undef will_free
#define will_free(x, y)  ({						\
	void *__x = (x); size_t __y = (y);				\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_FREE,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	if (__x) {							\
		_HA_ATOMIC_INC(&_.calls);				\
		_HA_ATOMIC_ADD(&_.size, __y);				\
	}								\
})

#undef ha_free
#define ha_free(x)  ({							\
	typeof(x) __x = (x);						\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_FREE,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
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
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_MALLOC,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __x);					\
	malloc(__x);							\
})

#undef realloc
#define realloc(x,y)  ({						\
	void *__x = (x); size_t __y = (y);				\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_REALLOC,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __y);					\
	realloc(__x,__y);						\
})

#undef strdup
#define strdup(x)  ({							\
	const char *__x = (x); size_t __y = strlen(__x); 		\
	static struct mem_stats _ __attribute__((used,__section__("mem_stats"),__aligned__(sizeof(void*)))) = { \
		.caller = {						\
			.file = __FILE__, .line = __LINE__,		\
			.what = MEM_STATS_TYPE_STRDUP,			\
			.func = __func__,				\
		},							\
	};								\
	HA_WEAK(__start_mem_stats);					\
	HA_WEAK(__stop_mem_stats);					\
	_HA_ATOMIC_INC(&_.calls);					\
	_HA_ATOMIC_ADD(&_.size, __y);					\
	strdup(__x);							\
})
#else // DEBUG_MEM_STATS

#define will_free(x, y) do { } while (0)

#endif /* DEBUG_MEM_STATS*/

/* Add warnings to users of such functions. These will be reported at link time
 * indicating what file name and line used them. The goal is to remind their
 * users that these are extremely unsafe functions that never have a valid
 * reason for being used.
 */
#undef strcat
__attribute__warning("\n"
"  * WARNING! strcat() must never be used, because there is no convenient way\n"
"  *          to use it that is safe. Use memcpy() instead!\n")
extern char *strcat(char *__restrict dest, const char *__restrict src);

#undef strcpy
__attribute__warning("\n"
"  * WARNING! strcpy() must never be used, because there is no convenient way\n"
"  *          to use it that is safe. Use memcpy() or strlcpy2() instead!\n")
extern char *strcpy(char *__restrict dest, const char *__restrict src);

#undef strncat
__attribute__warning("\n"
"  * WARNING! strncat() must never be used, because there is no convenient way\n"
"  *          to use it that is safe. Use memcpy() instead!\n")
extern char *strncat(char *__restrict dest, const char *__restrict src, size_t n);

#undef sprintf
__attribute__warning("\n"
"  * WARNING! sprintf() must never be used, because there is no convenient way\n"
"  *          to use it that is safe. Use snprintf() instead!\n")
extern int sprintf(char *__restrict dest, const char *__restrict fmt, ...);

#if defined(_VA_LIST_DEFINED) || defined(_VA_LIST_DECLARED) || defined(_VA_LIST)
#undef vsprintf
__attribute__warning("\n"
"  * WARNING! vsprintf() must never be used, because there is no convenient way\n"
"  *          to use it that is safe. Use vsnprintf() instead!\n")
extern int vsprintf(char *__restrict dest, const char *__restrict fmt, va_list ap);
#endif

#endif /* _HAPROXY_BUG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
