/*
 * include/haproxy/compiler.h
 * This files contains some compiler-specific settings.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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
 */

#ifndef _HAPROXY_COMPILER_H
#define _HAPROXY_COMPILER_H

/* leave a chance to the compiler to bring its own definitions first; this
 * will cause cdefs.h to be included on systems which have it.
 */
#include <inttypes.h>

#ifdef DEBUG_USE_ABORT
#include <stdlib.h>
#endif

/*
 * Gcc before 3.0 needs [0] to declare a variable-size array
 */
#ifndef VAR_ARRAY
#if defined(__GNUC__) && (__GNUC__ < 3)
#define VAR_ARRAY	0
#else
#define VAR_ARRAY
#endif
#endif

/* This is used to test if a macro is defined and equals 1. The principle is
 * that the macro is passed as a value and its value concatenated to the word
 * "comma_for_one" to form a new macro name. The macro "comma_for_one1" equals
 * one comma, which, once used in an argument, will shift all of them by one,
 * so that we can use this to concatenate both a 1 and a 0 and always pick the
 * second one.
 */
#define comma_for_one1 ,
#define _____equals_1(x, y, ...) (y)
#define ____equals_1(x, ...) _____equals_1(x, 0)
#define ___equals_1(x)       ____equals_1(comma_for_one ## x 1)
#define __equals_1(x)        ___equals_1(x)

/* gcc 5 and clang 3 brought __has_attribute(), which is not well documented in
 * the case of gcc, but is convenient since handled at the preprocessor level.
 * In both cases it's possible to test for __has_attribute() using ifdef. When
 * not defined we remap this to the __has_attribute_<name> macro so that we'll
 * later be able to implement on a per-compiler basis those which are missing,
 * by defining __has_attribute_<name> to 1.
 */
#ifndef __has_attribute
#define __has_attribute(x) __equals_1(__has_attribute_ ## x)
#endif

/* gcc 10 and clang 3 brought __has_builtin() to test if a builtin exists.
 * Just like above, if it doesn't exist, we remap it to a macro allowing us
 * to define these ourselves by defining __has_builtin_<name> to 1.
 */
#ifndef __has_builtin
#define __has_builtin(x) __equals_1(__has_builtin_ ## x)
#endif

/* The fallthrough attribute arrived with gcc 7, the same version that started
 * to emit the fallthrough warnings and to parse the comments. Comments do not
 * manage to stop the warning when preprocessing is split from compiling (e.g.
 * when building under distcc). Better encourage the use of a __fallthrough
 * statement instead. There are still limitations in that clang doesn't accept
 * it after a label; this is the reason why we're always preceding it with an
 * empty do-while.
 */
#if __has_attribute(fallthrough)
#  define __fallthrough do { } while (0); __attribute__((fallthrough))
#else
#  define __fallthrough do { } while (0)
#endif

#if !defined(__GNUC__)
/* Some versions of glibc irresponsibly redefine __attribute__() to empty for
 * non-gcc compilers, and as such, silently break all constructors with other
 * other compilers. Let's make sure such incompatibilities are detected if any,
 * or that the attribute is properly enforced.
 */
#undef __attribute__
#define __attribute__(x) __attribute__(x)
#endif

/* attribute(warning) was added in gcc 4.3 */
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#  define __has_attribute_warning 1
#endif

/* __attribute__warning(x) does __attribute__((warning(x))) if supported by the
 * compiler, otherwise __attribute__((deprecated)). Clang supports it since v14
 * but is a bit capricious in that it refuses a redefinition with a warning
 * attribute that wasn't there the first time. However it's OK with deprecated(x)
 * so better use this one. See: https://github.com/llvm/llvm-project/issues/56519
 */
#if defined(__clang__)
#  define __attribute__warning(x) __attribute__((deprecated(x)))
#elif __has_attribute(warning)
#  define __attribute__warning(x) __attribute__((warning(x)))
#else
#  define __attribute__warning(x) __attribute__((deprecated))
#endif

/* By default, gcc does not inline large chunks of code, but we want it to
 * respect our choices.
 */
#if !defined(forceinline)
#if !defined(__GNUC__) || (__GNUC__ < 3)
#define forceinline inline
#else
#define forceinline inline __attribute__((always_inline))
#endif
#endif

#ifndef __maybe_unused
/* silence the "unused" warnings without having to place painful #ifdefs.
 * For use with variables or functions.
 */
#define __maybe_unused __attribute__((unused))
#endif

/* TCC doesn't support weak attribute, sections etc and needs the more portable
 * obsolete linker model instead.
 */
#if defined(__TINYC__) && !defined(USE_OBSOLETE_LINKER)
#define USE_OBSOLETE_LINKER 1
#endif

/* These macros are used to declare a section name for a variable.
 * WARNING: keep section names short, as MacOS limits them to 16 characters.
 * The _START and _STOP attributes have to be placed after the start and stop
 * weak symbol declarations, and are only used by MacOS.
 */
#if !defined(USE_OBSOLETE_LINKER)

#ifdef __APPLE__
#define HA_SECTION(s)           __attribute__((__section__("__DATA, " s)))
#define HA_SECTION_START(s)     __asm("section$start$__DATA$" s)
#define HA_SECTION_STOP(s)      __asm("section$end$__DATA$" s)
#else
#define HA_SECTION(s)           __attribute__((__section__(s)))
#define HA_SECTION_START(s)
#define HA_SECTION_STOP(s)
#endif

#else // obsolete linker below, let's just not force any section

#define HA_SECTION(s)
#define HA_SECTION_START(s)
#define HA_SECTION_STOP(s)

#endif // USE_OBSOLETE_LINKER

/* Declare a symbol as weak if possible, otherwise global. Since we don't want to
 * error on multiple definitions, the symbol is declared weak. On MacOS ".weak"
 * does not exist and we must continue to use ".globl" instead. Note that
 * ".global" is to be avoided on other platforms as llvm complains about it
 * being used for symbols declared as weak elsewhere in the code. It may or may
 * not work depending on linkers and assemblers, this is only for advanced use
 * anyway (and most likely it will only work with !USE_OBSOLETE_LINKER).
 */
#if defined(__APPLE__)
#  define __HA_WEAK(sym)   __asm__(".globl " #sym)
#else
#  define __HA_WEAK(sym)   __asm__(".weak " #sym)
#endif
#define HA_WEAK(sym)    __HA_WEAK(sym)

/* declare a symbol as global */
#define __HA_GLOBL(sym)   __asm__(".globl " #sym)
#define HA_GLOBL(sym)     __HA_GLOBL(sym)

/* use this attribute on a variable to move it to the read_mostly section */
#if !defined(__read_mostly)
#define __read_mostly           HA_SECTION("read_mostly")
#endif

/* __builtin_unreachable() was added in gcc 4.5 */
#if defined(__GNUC__) && (__GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
#define __has_builtin___builtin_unreachable 1
#endif

/* This allows gcc to know that some locations are never reached, for example
 * after a longjmp() in the Lua code, hence that some errors caught by such
 * methods cannot propagate further. This is important with gcc versions 6 and
 * above which can more aggressively detect null dereferences. The builtin
 * below was introduced in gcc 4.5, and before it we didn't care.
 */
#ifdef DEBUG_USE_ABORT
#define my_unreachable() abort()
#else
#if __has_builtin(__builtin_unreachable)
#define my_unreachable() __builtin_unreachable()
#else
#define my_unreachable() do { } while (1)
#endif
#endif

/* By using an unreachable statement, we can tell the compiler that certain
 * conditions are not expected to be met and let it arrange as it wants to
 * optimize some checks away. The principle is to place a test on the condition
 * and call unreachable upon a match. It may also help static code analyzers
 * know that some conditions are not supposed to happen. This can only be used
 * with compilers that support it, and we do not want to emit any static code
 * for other ones, so we use a construct that the compiler should easily be
 * able to optimize away. Clang also has __builtin_assume() since at least 3.x.
 * In addition, ASSUME_NONNULL() tells the compiler that the pointer argument
 * will never be null. If not supported, it will be disguised via an assembly
 * step.
 */
#if __has_builtin(__builtin_assume)
# define ASSUME(expr) __builtin_assume(expr)
# define ASSUME_NONNULL(p) ({ typeof(p) __p = (p); __builtin_assume(__p != NULL); (__p); })
#elif __has_builtin(__builtin_unreachable)
# define ASSUME(expr) do { if (!(expr)) __builtin_unreachable(); } while (0)
# define ASSUME_NONNULL(p) ({ typeof(p) __p = (p); if (__p == NULL) __builtin_unreachable(); (__p); })
#else
# define ASSUME(expr) do { if (!(expr)) break; } while (0)
# define ASSUME_NONNULL(p) ({ typeof(p) __p = (p); asm("" : "=rm"(__p) : "0"(__p)); __p; })
#endif

/* This prevents the compiler from folding multiple identical code paths into a
 * single one, by adding a dependency on the line number in the path. This may
 * typically happen on function tails, or purposely placed abort() before an
 * unreachable() statement, due to the compiler performing an Identical Code
 * Folding optimization. This macro is aimed at helping with code tracing in
 * crash dumps and may also be used for specific optimizations. One known case
 * is gcc-4.7 and 4.8 which aggressively fold multiple ABORT_NOW() exit points
 * and which causes wrong line numbers to be reported by the debugger (note
 * that even newer compilers do this when using abort()). Please keep in mind
 * that nothing prevents the compiler from folding the code after that point,
 * but at least it will not fold the code before.
 */
#define DO_NOT_FOLD() do { asm volatile("" :: "i"(__LINE__)); } while (0)

/* This macro may be used to block constant propagation that lets the compiler
 * detect a possible NULL dereference on a variable resulting from an explicit
 * assignment in an impossible check. Sometimes a function is called which does
 * safety checks and returns NULL if safe conditions are not met. The place
 * where it's called cannot hit this condition and dereferencing the pointer
 * without first checking it will make the compiler emit a warning about a
 * "potential null pointer dereference" which is hard to work around. This
 * macro "washes" the pointer and prevents the compiler from emitting tests
 * branching to undefined instructions. It may only be used when the developer
 * is absolutely certain that the conditions are guaranteed and that the
 * pointer passed in argument cannot be NULL by design.
 */
#define ALREADY_CHECKED(p) do { asm("" : "=rm"(p) : "0"(p)); } while (0)

/* same as above but to be used to pass the input value to the output but
 * without letting the compiler know about its initial properties.
 */
#define DISGUISE(v) ({ typeof(v) __v = (v); ALREADY_CHECKED(__v); __v; })

/* Implements a static event counter where it's used. This is typically made to
 * report some warnings only once, either during boot or at runtime. It only
 * returns true on the very first call, and zero later. It's thread-safe and
 * uses a single byte of memory per call place. It relies on the atomic xchg
 * defined in atomic.h which is also part of the common API.
 */
#define ONLY_ONCE() ({ static char __cnt; !_HA_ATOMIC_XCHG(&__cnt, 1); })

/* makes a string from a constant (number or macro), avoids the need for
 * printf("%d") format just to dump a setting limit or value in an error
 * message. We use two levels so that macros are resolved.
 */
#define _TOSTR(x) #x
#define TOSTR(x) _TOSTR(x)

/*
 * Gcc >= 3 provides the ability for the program to give hints to the
 * compiler about what branch of an if is most likely to be taken. This
 * helps the compiler produce the most compact critical paths, which is
 * generally better for the cache and to reduce the number of jumps.
 */
#if !defined(likely)
#if !defined(__GNUC__) || (__GNUC__ < 3)
#define __builtin_expect(x,y) (x)
#define likely(x) (x)
#define unlikely(x) (x)
#else
#define likely(x) (__builtin_expect((x) != 0, 1))
#define unlikely(x) (__builtin_expect((x) != 0, 0))
#endif
#endif

/* Define the missing __builtin_prefetch() for tcc. */
#if defined(__TINYC__)
#define __builtin_prefetch(addr, ...) do { } while (0)
#endif

#ifndef __GNUC_PREREQ__
#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
#define __GNUC_PREREQ__(ma, mi) \
        (__GNUC__ > (ma) || __GNUC__ == (ma) && __GNUC_MINOR__ >= (mi))
#else
#define __GNUC_PREREQ__(ma, mi) 0
#endif
#endif

#ifndef offsetof
#if __GNUC_PREREQ__(4, 1)
#define offsetof(type, field)  __builtin_offsetof(type, field)
#else
#define offsetof(type, field) \
        ((size_t)(uintptr_t)((const volatile void *)&((type *)0)->field))
#endif
#endif

/* Linux-like "container_of". It returns a pointer to the structure of type
 * <type> which has its member <name> stored at address <ptr>.
 */
#ifndef container_of
#define container_of(ptr, type, name) ((type *)(((void *)(ptr)) - ((long)&((type *)0)->name)))
#endif

/* returns a pointer to the structure of type <type> which has its member <name>
 * stored at address <ptr>, unless <ptr> is 0, in which case 0 is returned.
 */
#ifndef container_of_safe
#define container_of_safe(ptr, type, name) \
	({ void *__p = (ptr); \
		__p ? (type *)(__p - ((long)&((type *)0)->name)) : (type *)0; \
	})
#endif


/* From gcc 6 and above, enum values may have attributes */
#if __GNUC_PREREQ__(6, 0)
#define ENUM_ATTRIBUTE(x) __attribute__(x)
#else
#define ENUM_ATTRIBUTE(x)
#endif

/* Some architectures have a double-word CAS, sometimes even dual-8 bytes.
 * Some architectures support unaligned accesses, others are fine with them
 * but only for non-atomic operations. Also mention those supporting unaligned
 * accesses and being little endian, and those where unaligned accesses are
 * known to be fast (almost as fast as aligned ones).
 */
#if defined(__x86_64__)
#define HA_UNALIGNED
#define HA_UNALIGNED_LE
#define HA_UNALIGNED_LE64
#define HA_UNALIGNED_FAST
#define HA_UNALIGNED_ATOMIC
#define HA_HAVE_CAS_DW
#define HA_CAS_IS_8B
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#define HA_UNALIGNED
#define HA_UNALIGNED_LE
#define HA_UNALIGNED_ATOMIC
#elif defined (__aarch64__) || defined(__ARM_ARCH_8A)
#define HA_UNALIGNED
#define HA_UNALIGNED_LE
#define HA_UNALIGNED_LE64
#define HA_UNALIGNED_FAST
#define HA_HAVE_CAS_DW
#define HA_CAS_IS_8B
#elif defined(__arm__) && (defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__))
#define HA_UNALIGNED
#define HA_UNALIGNED_LE
#define HA_UNALIGNED_FAST
#define HA_HAVE_CAS_DW
#endif

/*********************** IMPORTANT NOTE ABOUT ALIGNMENT **********************\
 * Alignment works fine for variables. It also works on types and struct     *
 * members by propagating the alignment to the container struct itself,      *
 * but this requires that variables of the affected type are properly        *
 * aligned themselves. While regular variables will always abide, those      *
 * allocated using malloc() will not! Most platforms provide posix_memalign()*
 * for this, but it's not available everywhere. As such one ought not to use *
 * these alignment declarations inside structures that are dynamically       *
 * allocated. If the purpose is only to avoid false sharing of cache lines   *
 * for multi_threading, see THREAD_PAD() below.                              *
\*****************************************************************************/

/* sets alignment for current field or variable */
#ifndef ALIGNED
#define ALIGNED(x) __attribute__((aligned(x)))
#endif

/* sets alignment only on architectures preventing unaligned atomic accesses */
#ifndef MAYBE_ALIGNED
#ifndef HA_UNALIGNED
#define MAYBE_ALIGNED(x)  ALIGNED(x)
#else
#define MAYBE_ALIGNED(x)
#endif
#endif

/* sets alignment only on architectures preventing unaligned atomic accesses */
#ifndef ATOMIC_ALIGNED
#ifndef HA_UNALIGNED_ATOMIC
#define ATOMIC_ALIGNED(x)  ALIGNED(x)
#else
#define ATOMIC_ALIGNED(x)
#endif
#endif

/* sets alignment for current field or variable only when threads are enabled.
 * Typically used to respect cache line alignment to avoid false sharing.
 */
#ifndef THREAD_ALIGNED
#ifdef USE_THREAD
#define THREAD_ALIGNED(x) __attribute__((aligned(x)))
#else
#define THREAD_ALIGNED(x)
#endif
#endif

/* add a mandatory alignment for next fields in a structure */
#ifndef ALWAYS_ALIGN
#define ALWAYS_ALIGN(x)  union { } ALIGNED(x)
#endif

/* add an optional alignment for next fields in a structure, only for archs
 * which do not support unaligned accesses.
 */
#ifndef MAYBE_ALIGN
#ifndef HA_UNALIGNED
#define MAYBE_ALIGN(x)  union { } ALIGNED(x)
#else
#define MAYBE_ALIGN(x)
#endif
#endif

/* add an optional alignment for next fields in a structure, only for archs
 * which do not support unaligned accesses for atomic operations.
 */
#ifndef ATOMIC_ALIGN
#ifndef HA_UNALIGNED_ATOMIC
#define ATOMIC_ALIGN(x)  union { } ALIGNED(x)
#else
#define ATOMIC_ALIGN(x)
#endif
#endif

/* add an optional alignment for next fields in a structure, only when threads
 * are enabled. Typically used to respect cache line alignment to avoid false
 * sharing.
 */
#ifndef THREAD_ALIGN
#ifdef USE_THREAD
#define THREAD_ALIGN(x) union { } ALIGNED(x)
#else
#define THREAD_ALIGN(x)
#endif
#endif

/* add optional padding of the specified size between fields in a structure,
 * only when threads are enabled. This is used to avoid false sharing of cache
 * lines for dynamically allocated structures which cannot guarantee alignment.
 */
#ifndef THREAD_PAD
# ifdef USE_THREAD
#  define __THREAD_PAD(x,l)  char __pad_##l[x]
#  define _THREAD_PAD(x,l)   __THREAD_PAD(x, l)
#  define THREAD_PAD(x)      _THREAD_PAD(x, __LINE__)
# else
#  define THREAD_PAD(x)
# endif
#endif

/* The THREAD_LOCAL type attribute defines thread-local storage and is defined
 * to __thread when threads are enabled or empty when disabled.
 */
#ifdef USE_THREAD
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif

/* The __decl_thread() statement is shows the argument when threads are enabled
 * or hides it when disabled. The purpose is to condition the presence of some
 * variables or struct members to the fact that threads are enabled, without
 * having to enclose them inside a #ifdef USE_THREAD/#endif clause.
 */
#ifdef USE_THREAD
#define __decl_thread(decl) decl
#else
#define __decl_thread(decl)
#endif

/* clang has a __has_feature() macro which reports true/false on a number of
 * internally supported features. Let's make sure this macro is always defined
 * and returns zero when not supported.
 */
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#endif /* _HAPROXY_COMPILER_H */
