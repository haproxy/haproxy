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

#if !defined(__GNUC__)
/* Some versions of glibc irresponsibly redefine __attribute__() to empty for
 * non-gcc compilers, and as such, silently break all constructors with other
 * other compilers. Let's make sure such incompatibilities are detected if any,
 * or that the attribute is properly enforced.
 */
#undef __attribute__
#define __attribute__(x) __attribute__(x)
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

/* silence the "unused" warnings without having to place painful #ifdefs.
 * For use with variables or functions.
 */
#define __maybe_unused __attribute__((unused))

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

/* use this attribute on a variable to move it to the read_mostly section */
#if !defined(__DragonFly__)
#define __read_mostly           HA_SECTION("read_mostly")
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
#if __GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#define my_unreachable() __builtin_unreachable()
#else
#define my_unreachable()
#endif
#endif

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
