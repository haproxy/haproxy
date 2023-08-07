/* generic atomic operations used by progressive locks
 *
 * Copyright (C) 2012-2022 Willy Tarreau <w@1wt.eu>
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

#ifndef PL_ATOMIC_OPS_H
#define PL_ATOMIC_OPS_H

/* The definitions below exist in two forms:
 *   - fallback form (_pl_*)
 *   - preferred form (pl_*)
 *
 * As a general rule, given that C11 atomics tend to offer more flexibility to
 * the compiler, these should set the preferred form, and the arch-specific
 * code should set the fallback code. But it's possible for arch-specific code
 * to set a preferred form, in which case it will simply be used over the other
 * ones.
 */

/*
 * Architecture-specific versions of the various operations
 */

/*
 * ###### ix86 / x86_64 below ######
 */
#if defined(__i386__) || defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)

/* for compilers supporting condition flags on output, let's directly return them */
#if defined(__GCC_ASM_FLAG_OUTPUTS__)
#define X86_COND_C_TO_REG(reg)  ""
#define X86_COND_Z_TO_REG(reg)  ""
#define X86_COND_NZ_TO_REG(reg) ""
#define X86_COND_C_RESULT(var)  "=@ccc"(var)
#define X86_COND_Z_RESULT(var)  "=@ccz"(var)
#define X86_COND_NZ_RESULT(var) "=@ccnz"(var)
#else
#define X86_COND_C_TO_REG(reg)  "sbb %" #reg ", %" #reg "\n\t"
#define X86_COND_Z_TO_REG(reg)  "sete %" #reg "\n\t"
#define X86_COND_NZ_TO_REG(reg) "setne %" #reg "\n\t"
#define X86_COND_C_RESULT(var)  "=r"(var)
#define X86_COND_Z_RESULT(var)  "=qm"(var)
#define X86_COND_NZ_RESULT(var) "=qm"(var)
#endif

/* CPU relaxation while waiting (PAUSE instruction on x86) */
#define pl_cpu_relax() do {                   \
		asm volatile("rep;nop\n");    \
	} while (0)

/* full memory barrier using mfence when SSE2 is supported, falling back to
 * "lock add %esp" (gcc uses "lock add" or "lock or").
 */
#if defined(__SSE2__)

#define _pl_mb() do {                                \
		asm volatile("mfence" ::: "memory"); \
	} while (0)

#elif defined(__x86_64__)

#define _pl_mb() do {                                                      \
		asm volatile("lock addl $0,0 (%%rsp)" ::: "memory", "cc"); \
	} while (0)

#else /* ix86 */

#define _pl_mb() do {                                                      \
		asm volatile("lock addl $0,0 (%%esp)" ::: "memory", "cc"); \
	} while (0)

#endif /* end of pl_mb() case for sse2/x86_64/x86 */

/* load/store barriers are nops on x86 */
#define _pl_mb_load()       do { asm volatile("" ::: "memory"); } while (0)
#define _pl_mb_store()      do { asm volatile("" ::: "memory"); } while (0)

/* atomic full/load/store are also nops on x86 */
#define _pl_mb_ato()        do { asm volatile("" ::: "memory"); } while (0)
#define _pl_mb_ato_load()   do { asm volatile("" ::: "memory"); } while (0)
#define _pl_mb_ato_store()  do { asm volatile("" ::: "memory"); } while (0)

/* atomic load: on x86 it's just a volatile read */
#define _pl_load_lax(ptr) _pl_load(ptr)
#define _pl_load(ptr) ({ typeof(*(ptr)) __ptr = *(volatile typeof(ptr))ptr; __ptr; })

/* atomic store: on x86 it's just a volatile write */
#define _pl_store_lax(ptr) _pl_store(ptr)
#define _pl_store(ptr, x) do { *((volatile typeof(ptr))(ptr)) = (typeof(*ptr))(x); } while (0)

/* increment integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define _pl_inc_lax(ptr) _pl_inc(ptr)
#define _pl_inc_acq(ptr) _pl_inc(ptr)
#define _pl_inc_rel(ptr) _pl_inc(ptr)
#define _pl_inc(ptr) (                                                        \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		asm volatile("lock incq %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incl %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incw %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incb %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_inc__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_inc__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* decrement integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define _pl_dec_lax(ptr) _pl_dec(ptr)
#define _pl_dec_acq(ptr) _pl_dec(ptr)
#define _pl_dec_rel(ptr) _pl_dec(ptr)
#define _pl_dec(ptr) (                                                        \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		asm volatile("lock decq %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decl %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decw %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decb %0\n"                                 \
			     X86_COND_NZ_TO_REG(1)                            \
			     : "+m" (*(ptr)), X86_COND_NZ_RESULT(ret)         \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_dec__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_dec__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* increment integer value pointed to by pointer <ptr>, no return */
#define pl_inc_noret_lax(ptr) pl_inc_noret(ptr)
#define pl_inc_noret_acq(ptr) pl_inc_noret(ptr)
#define pl_inc_noret_rel(ptr) pl_inc_noret(ptr)
#define pl_inc_noret(ptr) do {                                                \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock incq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock incl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock incw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock incb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_inc_noret__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_inc_noret__(__FILE__,__LINE__); \
	}                                                                     \
} while (0)

/* decrement integer value pointed to by pointer <ptr>, no return */
#define pl_dec_noret_lax(ptr) pl_dec_noret(ptr)
#define pl_dec_noret_acq(ptr) pl_dec_noret(ptr)
#define pl_dec_noret_rel(ptr) pl_dec_noret(ptr)
#define pl_dec_noret(ptr) do {                                                \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock decq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock decl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock decw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock decb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_dec_noret__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_dec_noret__(__FILE__,__LINE__); \
	}                                                                     \
} while (0)

/* add integer constant <x> to integer value pointed to by pointer <ptr>,
 * no return. Size of <x> is not checked.
 */
#define _pl_add_noret_lax(ptr, x) _pl_add_noret(ptr, x)
#define _pl_add_noret_acq(ptr, x) _pl_add_noret(ptr, x)
#define _pl_add_noret_rel(ptr, x) _pl_add_noret(ptr, x)
#define _pl_add_noret(ptr, x) do {                                            \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock addq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock addl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock addw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock addb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_add__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_add__(__FILE__,__LINE__);       \
	}                                                                     \
} while (0)

/* subtract integer constant <x> from integer value pointed to by pointer
 * <ptr>, no return. Size of <x> is not checked.
 */
#define _pl_sub_noret_lax(ptr, x) _pl_sub_noret(ptr, x)
#define _pl_sub_noret_acq(ptr, x) _pl_sub_noret(ptr, x)
#define _pl_sub_noret_rel(ptr, x) _pl_sub_noret(ptr, x)
#define _pl_sub_noret(ptr, x) do {                                            \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock subq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock subl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock subw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock subb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_sub__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_sub__(__FILE__,__LINE__);   \
	}                                                                     \
} while (0)

/* binary and integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define _pl_and_noret_lax(ptr, x) _pl_and_noret(ptr, x)
#define _pl_and_noret_acq(ptr, x) _pl_and_noret(ptr, x)
#define _pl_and_noret_rel(ptr, x) _pl_and_noret(ptr, x)
#define _pl_and_noret(ptr, x) do {                                            \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock andq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock andl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock andw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock andb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_and__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_and__(__FILE__,__LINE__);    \
	}                                                                     \
} while (0)

/* binary or integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define _pl_or_noret_lax(ptr, x) _pl_or_noret(ptr, x)
#define _pl_or_noret_acq(ptr, x) _pl_or_noret(ptr, x)
#define _pl_or_noret_rel(ptr, x) _pl_or_noret(ptr, x)
#define _pl_or_noret(ptr, x) do {                                             \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock orq %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock orl %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock orw %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock orb %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_or__(char *,int);     \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_or__(__FILE__,__LINE__);     \
	}                                                                     \
} while (0)

/* binary xor integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define _pl_xor_noret_lax(ptr, x) _pl_xor_noret(ptr, x)
#define _pl_xor_noret_acq(ptr, x) _pl_xor_noret(ptr, x)
#define _pl_xor_noret_rel(ptr, x) _pl_xor_noret(ptr, x)
#define _pl_xor_noret(ptr, x) do {                                            \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock xorq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock xorl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock xorw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock xorb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_xor__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xor__(__FILE__,__LINE__);            \
	}                                                                     \
} while (0)

/* test and reset bit <bit> in integer value pointed to by pointer <ptr>. Returns
 * 0 if the bit was not set, or ~0 of the same type as *ptr if it was set. Note
 * that there is no 8-bit equivalent operation.
 */
#define pl_btr_lax(ptr, bit) pl_btr(ptr, bit)
#define pl_btr_acq(ptr, bit) pl_btr(ptr, bit)
#define pl_btr_rel(ptr, bit) pl_btr(ptr, bit)
#define pl_btr(ptr, bit) (                                                    \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		asm volatile("lock btrq %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned long)(bit))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		asm volatile("lock btrl %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned int)(bit))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		asm volatile("lock btrw %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned short)(bit))                   \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_btr__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_btr__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* test and set bit <bit> in integer value pointed to by pointer <ptr>. Returns
 * 0 if the bit was not set, or ~0 of the same type as *ptr if it was set. Note
 * that there is no 8-bit equivalent operation.
 */
#define pl_bts_lax(ptr, bit) pl_bts(ptr, bit)
#define pl_bts_acq(ptr, bit) pl_bts(ptr, bit)
#define pl_bts_rel(ptr, bit) pl_bts(ptr, bit)
#define pl_bts(ptr, bit) (                                                   \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		asm volatile("lock btsq %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned long)(bit))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		asm volatile("lock btsl %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned int)(bit))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		asm volatile("lock btsw %2, %0\n\t"                           \
			     X86_COND_C_TO_REG(1)                             \
			     : "+m" (*(ptr)), X86_COND_C_RESULT(ret)          \
			     : "Ir" ((unsigned short)(bit))                   \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_bts__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_bts__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* Note: for an unclear reason, gcc's __sync_fetch_and_add() implementation
 * produces less optimal than hand-crafted asm code so let's implement here the
 * operations we need for the most common archs.
 */

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 * => THIS IS LEGACY, USE _pl_ldadd() INSTEAD.
 */
#define _pl_xadd(ptr, x) (                                                    \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		asm volatile("lock xaddq %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		asm volatile("lock xaddl %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		asm volatile("lock xaddw %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		asm volatile("lock xaddb %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xadd__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_xadd__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 */
#define _pl_ldadd_lax(ptr, x) _pl_ldadd(ptr, x)
#define _pl_ldadd_acq(ptr, x) _pl_ldadd(ptr, x)
#define _pl_ldadd_rel(ptr, x) _pl_ldadd(ptr, x)
#define _pl_ldadd(ptr, x) (                                                   \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		asm volatile("lock xaddq %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		asm volatile("lock xaddl %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		asm volatile("lock xaddw %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		asm volatile("lock xaddb %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_ldadd__(char *,int);  \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_ldadd__(__FILE__,__LINE__);  \
		0;                                                            \
	})                                                                    \
)

/* fetch-and-sub: fetch integer value pointed to by pointer <ptr>, add -<x> to
 * to <*ptr> and return the previous value.
 */
#define _pl_ldsub_lax(ptr, x) _pl_ldsub(ptr, x)
#define _pl_ldsub_acq(ptr, x) _pl_ldsub(ptr, x)
#define _pl_ldsub_rel(ptr, x) _pl_ldsub(ptr, x)
#define _pl_ldsub(ptr, x) (                                                   \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(-x);                      \
		asm volatile("lock xaddq %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(-x);                        \
		asm volatile("lock xaddl %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(-x);                    \
		asm volatile("lock xaddw %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(-x);                      \
		asm volatile("lock xaddb %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_ldsub__(char *,int);  \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_ldsub__(__FILE__,__LINE__);  \
		0;                                                            \
	})                                                                    \
)

/* exchange value <x> with integer value pointed to by pointer <ptr>, and return
 * previous <*ptr> value. <x> must be of the same size as <*ptr>.
 */
#define _pl_xchg(ptr, x) (                                                    \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		asm volatile("xchgq %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		asm volatile("xchgl %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		asm volatile("xchgw %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		asm volatile("xchgb %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xchg__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xchg__(__FILE__,__LINE__);           \
		0;                                                            \
	})                                                                    \
)

/* compare integer value <*ptr> with <old> and exchange it with <new> if
 * it matches, and return <old>. <old> and <new> must be of the same size as
 * <*ptr>.
 */
#define _pl_cmpxchg(ptr, old, new) (                                          \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		asm volatile("lock cmpxchgq %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned long)(new)),                    \
			       "0" ((unsigned long)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		asm volatile("lock cmpxchgl %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned int)(new)),                     \
			       "0" ((unsigned int)(old))                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		asm volatile("lock cmpxchgw %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned short)(new)),                   \
			       "0" ((unsigned short)(old))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock cmpxchgb %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned char)(new)),                    \
			       "0" ((unsigned char)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_cmpxchg__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
		__unsupported_argument_size_for_pl_cmpxchg__(__FILE__,__LINE__);       \
		0;                                                            \
	})                                                                    \
)

/*
 * ##### ARM64 (aarch64) below #####
 */
#elif defined(__aarch64__)

/* This was shown to improve fairness on modern ARMv8 such as Neoverse N1 */
#define pl_cpu_relax() do {				\
		asm volatile("isb" ::: "memory");	\
	} while (0)

/* full/load/store barriers */
#define _pl_mb()            do { asm volatile("dmb ish"   ::: "memory"); } while (0)
#define _pl_mb_load()       do { asm volatile("dmb ishld" ::: "memory"); } while (0)
#define _pl_mb_store()      do { asm volatile("dmb ishst" ::: "memory"); } while (0)

/* atomic full/load/store */
#define _pl_mb_ato()        do { asm volatile("dmb ish"   ::: "memory"); } while (0)
#define _pl_mb_ato_load()   do { asm volatile("dmb ishld" ::: "memory"); } while (0)
#define _pl_mb_ato_store()  do { asm volatile("dmb ishst" ::: "memory"); } while (0)

#endif // end of arch-specific code


/*
 * Generic code using the C11 __atomic API for functions not defined above.
 * These are usable from gcc-4.7 and clang. We'll simply rely on the macros
 * defining the memory orders to detect them. All operations are not
 * necessarily defined, so some fallbacks to the default methods might still
 * be necessary.
 */


#if defined(__ATOMIC_RELAXED) && defined(__ATOMIC_CONSUME) && defined(__ATOMIC_ACQUIRE) && \
    defined(__ATOMIC_RELEASE) && defined(__ATOMIC_ACQ_REL) && defined(__ATOMIC_SEQ_CST)

/* compiler-only memory barrier, for use around locks */
#ifndef pl_barrier
#define pl_barrier() __atomic_signal_fence(__ATOMIC_SEQ_CST)
#endif

/* full memory barrier */
#ifndef pl_mb
#define pl_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#endif

/* atomic load */
#ifndef pl_load_lax
#define pl_load_lax(ptr) __atomic_load_n(ptr, __ATOMIC_RELAXED)
#endif

#ifndef pl_load
#define pl_load(ptr)     __atomic_load_n(ptr, __ATOMIC_ACQUIRE)
#endif

/* atomic store */
#ifndef pl_store_lax
#define pl_store_lax(ptr, x) __atomic_store_n((ptr), (x), __ATOMIC_RELAXED)
#endif

#ifndef pl_store
#define pl_store(ptr, x) __atomic_store_n((ptr), (x), __ATOMIC_RELEASE)
#endif

/* increment integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#ifndef pl_inc_lax
#define pl_inc_lax(ptr) (__atomic_add_fetch((ptr), 1, __ATOMIC_RELAXED) != 0)
#endif

#ifndef pl_inc_acq
#define pl_inc_acq(ptr) (__atomic_add_fetch((ptr), 1, __ATOMIC_ACQUIRE) != 0)
#endif

#ifndef pl_inc_rel
#define pl_inc_rel(ptr) (__atomic_add_fetch((ptr), 1, __ATOMIC_RELEASE) != 0)
#endif

#ifndef pl_inc
#define pl_inc(ptr)     (__atomic_add_fetch((ptr), 1, __ATOMIC_SEQ_CST) != 0)
#endif

/* decrement integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#ifndef pl_dec_lax
#define pl_dec_lax(ptr) (__atomic_sub_fetch((ptr), 1, __ATOMIC_RELAXED) != 0)
#endif

#ifndef pl_dec_acq
#define pl_dec_acq(ptr) (__atomic_sub_fetch((ptr), 1, __ATOMIC_ACQUIRE) != 0)
#endif

#ifndef pl_dec_rel
#define pl_dec_rel(ptr) (__atomic_sub_fetch((ptr), 1, __ATOMIC_RELEASE) != 0)
#endif

#ifndef pl_dec
#define pl_dec(ptr)     (__atomic_sub_fetch((ptr), 1, __ATOMIC_SEQ_CST) != 0)
#endif

/* increment integer value pointed to by pointer <ptr>, no return */
#ifndef pl_inc_noret_lax
#define pl_inc_noret_lax(ptr)  ((void)__atomic_add_fetch((ptr), 1, __ATOMIC_RELAXED))
#endif

#ifndef pl_inc_noret_acq
#define pl_inc_noret_acq(ptr)  ((void)__atomic_add_fetch((ptr), 1, __ATOMIC_ACQUIRE))
#endif

#ifndef pl_inc_noret_rel
#define pl_inc_noret_relc(ptr) ((void)__atomic_add_fetch((ptr), 1, __ATOMIC_RELEASE))
#endif

#ifndef pl_inc_noret
#define pl_inc_noret(ptr)      ((void)__atomic_add_fetch((ptr), 1, __ATOMIC_SEQ_CST))
#endif

/* decrement integer value pointed to by pointer <ptr>, no return */
#ifndef pl_dec_noret_lax
#define pl_dec_noret_lax(ptr)  ((void)__atomic_sub_fetch((ptr), 1, __ATOMIC_RELAXED))
#endif

#ifndef pl_dec_noret_acq
#define pl_dec_noret_acq(ptr)  ((void)__atomic_sub_fetch((ptr), 1, __ATOMIC_ACQUIRE))
#endif

#ifndef pl_dec_noret_rel
#define pl_dec_noret_relc(ptr) ((void)__atomic_sub_fetch((ptr), 1, __ATOMIC_RELEASE))
#endif

#ifndef pl_dec_noret
#define pl_dec_noret(ptr)      ((void)__atomic_sub_fetch((ptr), 1, __ATOMIC_SEQ_CST))
#endif

/* add integer constant <x> to integer value pointed to by pointer <ptr>,
 * no return. Size of <x> is not checked.
 */
#ifndef pl_add_lax
#define pl_add_lax(ptr, x)  (__atomic_add_fetch((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_add_acq
#define pl_add_acq(ptr, x)  (__atomic_add_fetch((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_add_rel
#define pl_add_relc(ptr, x) (__atomic_add_fetch((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_add
#define pl_add(ptr, x)      (__atomic_add_fetch((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* subtract integer constant <x> from integer value pointed to by pointer
 * <ptr>, no return. Size of <x> is not checked.
 */
#ifndef pl_sub_lax
#define pl_sub_lax(ptr, x)  (__atomic_sub_fetch((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_sub_acq
#define pl_sub_acq(ptr, x)  (__atomic_sub_fetch((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_sub_rel
#define pl_sub_relc(ptr, x) (__atomic_sub_fetch((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_sub
#define pl_sub(ptr, x)      (__atomic_sub_fetch((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* binary and integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#ifndef pl_and_lax
#define pl_and_lax(ptr, x)  (__atomic_and_fetch((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_and_acq
#define pl_and_acq(ptr, x)  (__atomic_and_fetch((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_and_rel
#define pl_and_relc(ptr, x) (__atomic_and_fetch((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_and
#define pl_and(ptr, x)      (__atomic_and_fetch((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* binary or integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#ifndef pl_or_lax
#define pl_or_lax(ptr, x)   (__atomic_or_fetch((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_or_acq
#define pl_or_acq(ptr, x)   (__atomic_or_fetch((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_or_rel
#define pl_or_relc(ptr, x)  (__atomic_or_fetch((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_or
#define pl_or(ptr, x)       (__atomic_or_fetch((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* binary xor integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#ifndef pl_xor_lax
#define pl_xor_lax(ptr, x)  (__atomic_xor_fetch((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_xor_acq
#define pl_xor_acq(ptr, x)  (__atomic_xor_fetch((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_xor_rel
#define pl_xor_relc(ptr, x) (__atomic_xor_fetch((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_xor
#define pl_xor(ptr, x)      (__atomic_xor_fetch((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 * => THIS IS LEGACY, USE pl_ldadd() INSTEAD.
 */
#ifndef pl_xadd
#define pl_xadd(ptr, x) (__atomic_fetch_add((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* exchange value <x> with integer value pointed to by pointer <ptr>, and return
 * previous <*ptr> value. <x> must be of the same size as <*ptr>.
 */
#ifndef pl_xchg
#define pl_xchg(ptr, x) (__atomic_exchange_n((ptr), (x), __ATOMIC_SEQ_CST))
#endif

/* compare integer value <*ptr> with <old> and exchange it with <new> if
 * it matches, and return <old>. <old> and <new> must be of the same size as
 * <*ptr>.
 */
#ifndef pl_cmpxchg
#define pl_cmpxchg(ptr, old, new) ({					\
	typeof(*ptr) __old = (old);					\
	__atomic_compare_exchange_n((ptr), &__old, (new), 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED); \
	__old; })
#endif

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 */
#ifndef pl_ldadd_lax
#define pl_ldadd_lax(ptr, x)    (__atomic_fetch_add((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_ldadd_acq
#define pl_ldadd_acq(ptr, x)    (__atomic_fetch_add((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_ldadd_rel
#define pl_ldadd_relc(ptr, x)   (__atomic_fetch_add((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_ldadd
#define pl_ldadd(ptr, x)        (__atomic_fetch_add((ptr), (x), __ATOMIC_SEQ_CST))
#endif


#ifndef pl_ldand_lax
#define pl_ldand_lax(ptr, x)    (__atomic_fetch_and((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_ldand_acq
#define pl_ldand_acq(ptr, x)    (__atomic_fetch_and((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_ldand_rel
#define pl_ldand_relc(ptr, x)   (__atomic_fetch_and((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_ldand
#define pl_ldand(ptr, x)        (__atomic_fetch_and((ptr), (x), __ATOMIC_SEQ_CST))
#endif


#ifndef pl_ldor_lax
#define pl_ldor_lax(ptr, x)     (__atomic_fetch_or((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_ldor_acq
#define pl_ldor_acq(ptr, x)     (__atomic_fetch_or((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_ldor_rel
#define pl_ldor_relc(ptr, x)    (__atomic_fetch_or((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_ldor
#define pl_ldor(ptr, x)         (__atomic_fetch_or((ptr), (x), __ATOMIC_SEQ_CST))
#endif


#ifndef pl_ldsub_lax
#define pl_ldsub_lax(ptr, x)    (__atomic_fetch_sub((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_ldsub_acq
#define pl_ldsub_acq(ptr, x)    (__atomic_fetch_sub((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_ldsub_rel
#define pl_ldsub_relc(ptr, x)   (__atomic_fetch_sub((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_ldsub
#define pl_ldsub(ptr, x)        (__atomic_fetch_sub((ptr), (x), __ATOMIC_SEQ_CST))
#endif


#ifndef pl_ldxor_lax
#define pl_ldxor_lax(ptr, x)    (__atomic_fetch_xor((ptr), (x), __ATOMIC_RELAXED))
#endif

#ifndef pl_ldxor_acq
#define pl_ldxor_acq(ptr, x)    (__atomic_fetch_xor((ptr), (x), __ATOMIC_ACQUIRE))
#endif

#ifndef pl_ldxor_rel
#define pl_ldxor_relc(ptr, x)   (__atomic_fetch_xor((ptr), (x), __ATOMIC_RELEASE))
#endif

#ifndef pl_ldxor
#define pl_ldxor(ptr, x)        (__atomic_fetch_xor((ptr), (x), __ATOMIC_SEQ_CST))
#endif

#endif /* end of C11 atomics */


/*
 * Automatically remap to fallback code when available. This allows the arch
 * specific code above to be used as an immediate fallback for missing C11
 * definitions. Everything not defined will use the generic code at the end.
 */

#if !defined(pl_cpu_relax) && defined(_pl_cpu_relax)
# define pl_cpu_relax _pl_cpu_relax
#endif

#if !defined(pl_barrier) && defined(_pl_barrier)
# define pl_barrier _pl_barrier
#endif

#if !defined(pl_mb) && defined(_pl_mb)
# define pl_mb _pl_mb
#endif

#if !defined(pl_mb_load) && defined(_pl_mb_load)
# define pl_mb_load _pl_mb_load
#endif

#if !defined(pl_mb_store) && defined(_pl_mb_store)
# define pl_mb_store _pl_mb_store
#endif

#if !defined(pl_mb_ato) && defined(_pl_mb_ato)
# define pl_mb_ato _pl_mb_ato
#endif

#if !defined(pl_mb_ato_load) && defined(_pl_mb_ato_load)
# define pl_mb_ato_load _pl_mb_ato_load
#endif

#if !defined(pl_mb_ato_store) && defined(_pl_mb_ato_store)
# define pl_mb_ato_store _pl_mb_ato_store
#endif


#if !defined(pl_load) && defined(_pl_load)
#define pl_load _pl_load
#endif

#if !defined(pl_load_lax) && defined(_pl_load_lax)
#define pl_load_lax _pl_load_lax
#endif

#if !defined(pl_store) && defined(_pl_store)
#define pl_store _pl_store
#endif

#if !defined(pl_store_lax) && defined(_pl_store_lax)
#define pl_store_lax _pl_store_lax
#endif


#if !defined(pl_inc_noret_lax) && defined(_pl_inc_noret_lax)
# define pl_inc_noret_lax _pl_inc_noret_lax
#endif

#if !defined(pl_inc_noret_acq) && defined(_pl_inc_noret_acq)
# define pl_inc_noret_acq _pl_inc_noret_acq
#endif

#if !defined(pl_inc_noret_rel) && defined(_pl_inc_noret_rel)
# define pl_inc_noret_rel _pl_inc_noret_rel
#endif

#if !defined(pl_inc_noret) && defined(_pl_inc_noret)
# define pl_inc_noret _pl_inc_noret
#endif


#if !defined(pl_dec_noret_lax) && defined(_pl_dec_noret_lax)
# define pl_dec_noret_lax _pl_dec_noret_lax
#endif

#if !defined(pl_dec_noret_acq) && defined(_pl_dec_noret_acq)
# define pl_dec_noret_acq _pl_dec_noret_acq
#endif

#if !defined(pl_dec_noret_rel) && defined(_pl_dec_noret_rel)
# define pl_dec_noret_rel _pl_dec_noret_rel
#endif

#if !defined(pl_dec_noret) && defined(_pl_dec_noret)
# define pl_dec_noret _pl_dec_noret
#endif


#if !defined(pl_inc_lax) && defined(_pl_inc_lax)
# define pl_inc_lax _pl_inc_lax
#endif

#if !defined(pl_inc_acq) && defined(_pl_inc_acq)
# define pl_inc_acq _pl_inc_acq
#endif

#if !defined(pl_inc_rel) && defined(_pl_inc_rel)
# define pl_inc_rel _pl_inc_rel
#endif

#if !defined(pl_inc) && defined(_pl_inc)
# define pl_inc _pl_inc
#endif


#if !defined(pl_dec_lax) && defined(_pl_dec_lax)
# define pl_dec_lax _pl_dec_lax
#endif

#if !defined(pl_dec_acq) && defined(_pl_dec_acq)
# define pl_dec_acq _pl_dec_acq
#endif

#if !defined(pl_dec_rel) && defined(_pl_dec_rel)
# define pl_dec_rel _pl_dec_rel
#endif

#if !defined(pl_dec) && defined(_pl_dec)
# define pl_dec _pl_dec
#endif


#if !defined(pl_add_lax) && defined(_pl_add_lax)
# define pl_add_lax _pl_add_lax
#endif

#if !defined(pl_add_acq) && defined(_pl_add_acq)
# define pl_add_acq _pl_add_acq
#endif

#if !defined(pl_add_rel) && defined(_pl_add_rel)
# define pl_add_rel _pl_add_rel
#endif

#if !defined(pl_add) && defined(_pl_add)
# define pl_add _pl_add
#endif


#if !defined(pl_add_noret_lax) && defined(_pl_add_noret_lax)
# define pl_add_noret_lax _pl_add_noret_lax
#endif

#if !defined(pl_add_noret_acq) && defined(_pl_add_noret_acq)
# define pl_add_noret_acq _pl_add_noret_acq
#endif

#if !defined(pl_add_noret_rel) && defined(_pl_add_noret_rel)
# define pl_add_noret_rel _pl_add_noret_rel
#endif

#if !defined(pl_add_noret) && defined(_pl_add_noret)
# define pl_add_noret _pl_add_noret
#endif

#if !defined(pl_and_lax) && defined(_pl_and_lax)
# define pl_and_lax _pl_and_lax
#endif

#if !defined(pl_and_acq) && defined(_pl_and_acq)
# define pl_and_acq _pl_and_acq
#endif

#if !defined(pl_and_rel) && defined(_pl_and_rel)
# define pl_and_rel _pl_and_rel
#endif

#if !defined(pl_and) && defined(_pl_and)
# define pl_and _pl_and
#endif


#if !defined(pl_and_noret_lax) && defined(_pl_and_noret_lax)
# define pl_and_noret_lax _pl_and_noret_lax
#endif

#if !defined(pl_and_noret_acq) && defined(_pl_and_noret_acq)
# define pl_and_noret_acq _pl_and_noret_acq
#endif

#if !defined(pl_and_noret_rel) && defined(_pl_and_noret_rel)
# define pl_and_noret_rel _pl_and_noret_rel
#endif

#if !defined(pl_and_noret) && defined(_pl_and_noret)
# define pl_and_noret _pl_and_noret
#endif


#if !defined(pl_or_lax) && defined(_pl_or_lax)
# define pl_or_lax _pl_or_lax
#endif

#if !defined(pl_or_acq) && defined(_pl_or_acq)
# define pl_or_acq _pl_or_acq
#endif

#if !defined(pl_or_rel) && defined(_pl_or_rel)
# define pl_or_rel _pl_or_rel
#endif

#if !defined(pl_or) && defined(_pl_or)
# define pl_or _pl_or
#endif


#if !defined(pl_or_noret_lax) && defined(_pl_or_noret_lax)
# define pl_or_noret_lax _pl_or_noret_lax
#endif

#if !defined(pl_or_noret_acq) && defined(_pl_or_noret_acq)
# define pl_or_noret_acq _pl_or_noret_acq
#endif

#if !defined(pl_or_noret_rel) && defined(_pl_or_noret_rel)
# define pl_or_noret_rel _pl_or_noret_rel
#endif

#if !defined(pl_or_noret) && defined(_pl_or_noret)
# define pl_or_noret _pl_or_noret
#endif


#if !defined(pl_xor_lax) && defined(_pl_xor_lax)
# define pl_xor_lax _pl_xor_lax
#endif

#if !defined(pl_xor_acq) && defined(_pl_xor_acq)
# define pl_xor_acq _pl_xor_acq
#endif

#if !defined(pl_xor_rel) && defined(_pl_xor_rel)
# define pl_xor_rel _pl_xor_rel
#endif

#if !defined(pl_xor) && defined(_pl_xor)
# define pl_xor _pl_xor
#endif


#if !defined(pl_xor_noret_lax) && defined(_pl_xor_noret_lax)
# define pl_xor_noret_lax _pl_xor_noret_lax
#endif

#if !defined(pl_xor_noret_acq) && defined(_pl_xor_noret_acq)
# define pl_xor_noret_acq _pl_xor_noret_acq
#endif

#if !defined(pl_xor_noret_rel) && defined(_pl_xor_noret_rel)
# define pl_xor_noret_rel _pl_xor_noret_rel
#endif

#if !defined(pl_xor_noret) && defined(_pl_xor_noret)
# define pl_xor_noret _pl_xor_noret
#endif


#if !defined(pl_sub_lax) && defined(_pl_sub_lax)
# define pl_sub_lax _pl_sub_lax
#endif

#if !defined(pl_sub_acq) && defined(_pl_sub_acq)
# define pl_sub_acq _pl_sub_acq
#endif

#if !defined(pl_sub_rel) && defined(_pl_sub_rel)
# define pl_sub_rel _pl_sub_rel
#endif

#if !defined(pl_sub) && defined(_pl_sub)
# define pl_sub _pl_sub
#endif


#if !defined(pl_sub_noret_lax) && defined(_pl_sub_noret_lax)
# define pl_sub_noret_lax _pl_sub_noret_lax
#endif

#if !defined(pl_sub_noret_acq) && defined(_pl_sub_noret_acq)
# define pl_sub_noret_acq _pl_sub_noret_acq
#endif

#if !defined(pl_sub_noret_rel) && defined(_pl_sub_noret_rel)
# define pl_sub_noret_rel _pl_sub_noret_rel
#endif

#if !defined(pl_sub_noret) && defined(_pl_sub_noret)
# define pl_sub_noret _pl_sub_noret
#endif


#if !defined(pl_btr_lax) && defined(_pl_btr_lax)
# define pl_btr_lax _pl_btr_lax
#endif

#if !defined(pl_btr_acq) && defined(_pl_btr_acq)
# define pl_btr_acq _pl_btr_acq
#endif

#if !defined(pl_btr_rel) && defined(_pl_btr_rel)
# define pl_btr_rel _pl_btr_rel
#endif

#if !defined(pl_btr) && defined(_pl_btr)
# define pl_btr _pl_btr
#endif


#if !defined(pl_bts_lax) && defined(_pl_bts_lax)
# define pl_bts_lax _pl_bts_lax
#endif

#if !defined(pl_bts_acq) && defined(_pl_bts_acq)
# define pl_bts_acq _pl_bts_acq
#endif

#if !defined(pl_bts_rel) && defined(_pl_bts_rel)
# define pl_bts_rel _pl_bts_rel
#endif

#if !defined(pl_bts) && defined(_pl_bts)
# define pl_bts _pl_bts
#endif


#if !defined(pl_xadd) && defined(_pl_xadd)
# define pl_xadd _pl_xadd
#endif

#if !defined(pl_cmpxchg) && defined(_pl_cmpxchg)
# define pl_cmpxchg _pl_cmpxchg
#endif

#if !defined(pl_xchg) && defined(_pl_xchg)
# define pl_xchg _pl_xchg
#endif


#if !defined(pl_ldadd_lax) && defined(_pl_ldadd_lax)
# define pl_ldadd_lax _pl_ldadd_lax
#endif

#if !defined(pl_ldadd_acq) && defined(_pl_ldadd_acq)
# define pl_ldadd_acq _pl_ldadd_acq
#endif

#if !defined(pl_ldadd_rel) && defined(_pl_ldadd_rel)
# define pl_ldadd_rel _pl_ldadd_rel
#endif

#if !defined(pl_ldadd) && defined(_pl_ldadd)
# define pl_ldadd _pl_ldadd
#endif


#if !defined(pl_ldand_lax) && defined(_pl_ldand_lax)
# define pl_ldand_lax _pl_ldand_lax
#endif

#if !defined(pl_ldand_acq) && defined(_pl_ldand_acq)
# define pl_ldand_acq _pl_ldand_acq
#endif

#if !defined(pl_ldand_rel) && defined(_pl_ldand_rel)
# define pl_ldand_rel _pl_ldand_rel
#endif

#if !defined(pl_ldand) && defined(_pl_ldand)
# define pl_ldand _pl_ldand
#endif


#if !defined(pl_ldor_lax) && defined(_pl_ldor_lax)
# define pl_ldor_lax _pl_ldor_lax
#endif

#if !defined(pl_ldor_acq) && defined(_pl_ldor_acq)
# define pl_ldor_acq _pl_ldor_acq
#endif

#if !defined(pl_ldor_rel) && defined(_pl_ldor_rel)
# define pl_ldor_rel _pl_ldor_rel
#endif

#if !defined(pl_ldor) && defined(_pl_ldor)
# define pl_ldor _pl_ldor
#endif


#if !defined(pl_ldxor_lax) && defined(_pl_ldxor_lax)
# define pl_ldxor_lax _pl_ldxor_lax
#endif

#if !defined(pl_ldxor_acq) && defined(_pl_ldxor_acq)
# define pl_ldxor_acq _pl_ldxor_acq
#endif

#if !defined(pl_ldxor_rel) && defined(_pl_ldxor_rel)
# define pl_ldxor_rel _pl_ldxor_rel
#endif

#if !defined(pl_ldxor) && defined(_pl_ldxor)
# define pl_ldxor _pl_ldxor
#endif


#if !defined(pl_ldsub_lax) && defined(_pl_ldsub_lax)
# define pl_ldsub_lax _pl_ldsub_lax
#endif

#if !defined(pl_ldsub_acq) && defined(_pl_ldsub_acq)
# define pl_ldsub_acq _pl_ldsub_acq
#endif

#if !defined(pl_ldsub_rel) && defined(_pl_ldsub_rel)
# define pl_ldsub_rel _pl_ldsub_rel
#endif

#if !defined(pl_ldsub) && defined(_pl_ldsub)
# define pl_ldsub _pl_ldsub
#endif


/*
 * Generic code using the __sync API for everything not defined above.
 */


/* CPU relaxation while waiting */
#ifndef pl_cpu_relax
#define pl_cpu_relax() do {             \
		asm volatile("");       \
	} while (0)
#endif

/* compiler-only memory barrier, for use around locks */
#ifndef pl_barrier
#define pl_barrier() do {			\
		asm volatile("" ::: "memory");	\
	} while (0)
#endif

/* full memory barrier */
#ifndef pl_mb
#define pl_mb() do {                    \
		__sync_synchronize();   \
	} while (0)
#endif

#ifndef pl_mb_load
#define pl_mb_load() pl_mb()
#endif

#ifndef pl_mb_store
#define pl_mb_store() pl_mb()
#endif

#ifndef pl_mb_ato
#define pl_mb_ato() pl_mb()
#endif

#ifndef pl_mb_ato_load
#define pl_mb_ato_load() pl_mb_ato()
#endif

#ifndef pl_mb_ato_store
#define pl_mb_ato_store() pl_mb_ato()
#endif

/* atomic load: volatile after a load barrier */
#ifndef pl_load
#define pl_load(ptr) ({							\
		typeof(*(ptr)) __pl_ret = ({				\
			pl_mb_load();					\
			*(volatile typeof(ptr))ptr;			\
		});							\
		__pl_ret;						\
	})
#endif

/* atomic store, old style using a CAS */
#ifndef pl_store
#define pl_store(ptr, x) do {						\
		typeof((ptr))  __pl_ptr = (ptr);			\
		typeof((x))    __pl_x = (x);				\
		typeof(*(ptr)) __pl_old;				\
		do {							\
			__pl_old = *__pl_ptr;				\
		} while (!__sync_bool_compare_and_swap(__pl_ptr, __pl_old, __pl_x)); \
	} while (0)
#endif

#ifndef pl_inc_noret
#define pl_inc_noret(ptr)     do { __sync_add_and_fetch((ptr), 1); } while (0)
#endif

#ifndef pl_dec_noret
#define pl_dec_noret(ptr)     do { __sync_sub_and_fetch((ptr), 1); } while (0)
#endif

#ifndef pl_inc
#define pl_inc(ptr)           ({ __sync_add_and_fetch((ptr), 1);   })
#endif

#ifndef pl_dec
#define pl_dec(ptr)           ({ __sync_sub_and_fetch((ptr), 1);   })
#endif

#ifndef pl_add
#define pl_add(ptr, x)        ({ __sync_add_and_fetch((ptr), (x)); })
#endif

#ifndef pl_and
#define pl_and(ptr, x)        ({ __sync_and_and_fetch((ptr), (x)); })
#endif

#ifndef pl_or
#define pl_or(ptr, x)         ({ __sync_or_and_fetch((ptr), (x));  })
#endif

#ifndef pl_xor
#define pl_xor(ptr, x)        ({ __sync_xor_and_fetch((ptr), (x)); })
#endif

#ifndef pl_sub
#define pl_sub(ptr, x)        ({ __sync_sub_and_fetch((ptr), (x)); })
#endif

#ifndef pl_btr
#define pl_btr(ptr, bit)      ({ typeof(*(ptr)) __pl_t = ((typeof(*(ptr)))1) << (bit); \
                                 __sync_fetch_and_and((ptr), ~__pl_t) & __pl_t;	\
                              })
#endif

#ifndef pl_bts
#define pl_bts(ptr, bit)      ({ typeof(*(ptr)) __pl_t = ((typeof(*(ptr)))1) << (bit); \
                                 __sync_fetch_and_or((ptr), __pl_t) & __pl_t;	\
                              })
#endif

#ifndef pl_xadd
#define pl_xadd(ptr, x)       ({ __sync_fetch_and_add((ptr), (x)); })
#endif

#ifndef pl_cmpxchg
#define pl_cmpxchg(ptr, o, n) ({ __sync_val_compare_and_swap((ptr), (o), (n)); })
#endif

#ifndef pl_xchg
#define pl_xchg(ptr, x)	({						\
		typeof((ptr))  __pl_ptr = (ptr);			\
		typeof((x))    __pl_x = (x);				\
		typeof(*(ptr)) __pl_old;				\
		do {							\
			__pl_old = *__pl_ptr;				\
		} while (!__sync_bool_compare_and_swap(__pl_ptr, __pl_old, __pl_x)); \
		__pl_old;						\
	})
#endif

#ifndef pl_ldadd
#define pl_ldadd(ptr, x)        ({ __sync_fetch_and_add((ptr), (x)); })
#endif

#ifndef pl_ldand
#define pl_ldand(ptr, x)        ({ __sync_fetch_and_and((ptr), (x)); })
#endif

#ifndef pl_ldor
#define pl_ldor(ptr, x)         ({ __sync_fetch_and_or((ptr), (x));  })
#endif

#ifndef pl_ldxor
#define pl_ldxor(ptr, x)        ({ __sync_fetch_and_xor((ptr), (x)); })
#endif

#ifndef pl_ldsub
#define pl_ldsub(ptr, x)        ({ __sync_fetch_and_sub((ptr), (x)); })
#endif

/* certain _noret operations may be defined from the regular ones */
#if !defined(pl_inc_noret) && defined(pl_inc)
# define pl_inc_noret(ptr) (void)pl_inc(ptr)
#endif

#if !defined(pl_dec_noret) && defined(pl_dec)
# define pl_dec_noret(ptr) (void)pl_dec(ptr)
#endif

#if !defined(pl_add_noret) && defined(pl_add)
# define pl_add_noret(ptr, x) (void)pl_add(ptr, x)
#endif

#if !defined(pl_sub_noret) && defined(pl_sub)
# define pl_sub_noret(ptr, x) (void)pl_sub(ptr, x)
#endif

#if !defined(pl_or_noret) && defined(pl_or)
# define pl_or_noret(ptr, x) (void)pl_or(ptr, x)
#endif

#if !defined(pl_and_noret) && defined(pl_and)
# define pl_and_noret(ptr, x) (void)pl_and(ptr, x)
#endif

#if !defined(pl_xor_noret) && defined(pl_xor)
# define pl_xor_noret(ptr, x) (void)pl_xor(ptr, x)
#endif

/* certain memory orders may fallback to the generic seq_cst definition */

#if !defined(pl_load_lax) && defined(pl_load)
#define pl_load_lax pl_load
#endif


#if !defined(pl_store_lax) && defined(pl_store)
#define pl_store_lax pl_store
#endif


#if !defined(pl_inc_lax) && defined(pl_inc)
# define pl_inc_lax pl_inc
#endif
#if !defined(pl_inc_acq) && defined(pl_inc)
# define pl_inc_acq pl_inc
#endif
#if !defined(pl_inc_rel) && defined(pl_inc)
# define pl_inc_rel pl_inc
#endif


#if !defined(pl_dec_lax) && defined(pl_dec)
# define pl_dec_lax pl_dec
#endif
#if !defined(pl_dec_acq) && defined(pl_dec)
# define pl_dec_acq pl_dec
#endif

#if !defined(pl_dec_rel) && defined(pl_dec)
# define pl_dec_rel pl_dec
#endif


#if !defined(pl_inc_noret_lax) && defined(pl_inc_noret)
# define pl_inc_noret_lax pl_inc_noret
#endif

#if !defined(pl_inc_noret_acq) && defined(pl_inc_noret)
# define pl_inc_noret_acq pl_inc_noret
#endif

#if !defined(pl_inc_noret_rel) && defined(pl_inc_noret)
# define pl_inc_noret_rel pl_inc_noret
#endif


#if !defined(pl_dec_noret_lax) && defined(pl_dec_noret)
# define pl_dec_noret_lax pl_dec_noret
#endif

#if !defined(pl_dec_noret_acq) && defined(pl_dec_noret)
# define pl_dec_noret_acq pl_dec_noret
#endif

#if !defined(pl_dec_noret_rel) && defined(pl_dec_noret)
# define pl_dec_noret_rel pl_dec_noret
#endif


#if !defined(pl_add_lax) && defined(pl_add)
# define pl_add_lax pl_add
#endif

#if !defined(pl_add_acq) && defined(pl_add)
# define pl_add_acq pl_add
#endif

#if !defined(pl_add_rel) && defined(pl_add)
# define pl_add_rel pl_add
#endif


#if !defined(pl_sub_lax) && defined(pl_sub)
# define pl_sub_lax pl_sub
#endif

#if !defined(pl_sub_acq) && defined(pl_sub)
# define pl_sub_acq pl_sub
#endif

#if !defined(pl_sub_rel) && defined(pl_sub)
# define pl_sub_rel pl_sub
#endif


#if !defined(pl_and_lax) && defined(pl_and)
# define pl_and_lax pl_and
#endif

#if !defined(pl_and_acq) && defined(pl_and)
# define pl_and_acq pl_and
#endif

#if !defined(pl_and_rel) && defined(pl_and)
# define pl_and_rel pl_and
#endif


#if !defined(pl_or_lax) && defined(pl_or)
# define pl_or_lax pl_or
#endif

#if !defined(pl_or_acq) && defined(pl_or)
# define pl_or_acq pl_or
#endif

#if !defined(pl_or_rel) && defined(pl_or)
# define pl_or_rel pl_or
#endif


#if !defined(pl_xor_lax) && defined(pl_xor)
# define pl_xor_lax pl_xor
#endif

#if !defined(pl_xor_acq) && defined(pl_xor)
# define pl_xor_acq pl_xor
#endif

#if !defined(pl_xor_rel) && defined(pl_xor)
# define pl_xor_rel pl_xor
#endif


#if !defined(pl_add_noret_lax) && defined(pl_add_noret)
# define pl_add_noret_lax pl_add_noret
#endif

#if !defined(pl_add_noret_acq) && defined(pl_add_noret)
# define pl_add_noret_acq pl_add_noret
#endif

#if !defined(pl_add_noret_rel) && defined(pl_add_noret)
# define pl_add_noret_rel pl_add_noret
#endif


#if !defined(pl_sub_noret_lax) && defined(pl_sub_noret)
# define pl_sub_noret_lax pl_sub_noret
#endif

#if !defined(pl_sub_noret_acq) && defined(pl_sub_noret)
# define pl_sub_noret_acq pl_sub_noret
#endif

#if !defined(pl_sub_noret_rel) && defined(pl_sub_noret)
# define pl_sub_noret_rel pl_sub_noret
#endif


#if !defined(pl_and_noret_lax) && defined(pl_and_noret)
# define pl_and_noret_lax pl_and_noret
#endif

#if !defined(pl_and_noret_acq) && defined(pl_and_noret)
# define pl_and_noret_acq pl_and_noret
#endif

#if !defined(pl_and_noret_rel) && defined(pl_and_noret)
# define pl_and_noret_rel pl_and_noret
#endif


#if !defined(pl_or_noret_lax) && defined(pl_or_noret)
# define pl_or_noret_lax pl_or_noret
#endif

#if !defined(pl_or_noret_acq) && defined(pl_or_noret)
# define pl_or_noret_acq pl_or_noret
#endif

#if !defined(pl_or_noret_rel) && defined(pl_or_noret)
# define pl_or_noret_rel pl_or_noret
#endif


#if !defined(pl_xor_noret_lax) && defined(pl_xor_noret)
# define pl_xor_noret_lax pl_xor_noret
#endif

#if !defined(pl_xor_noret_acq) && defined(pl_xor_noret)
# define pl_xor_noret_acq pl_xor_noret
#endif

#if !defined(pl_xor_noret_rel) && defined(pl_xor_noret)
# define pl_xor_noret_rel pl_xor_noret
#endif


#if !defined(pl_btr_lax) && defined(pl_btr)
# define pl_btr_lax pl_btr
#endif

#if !defined(pl_btr_acq) && defined(pl_btr)
# define pl_btr_acq pl_btr
#endif

#if !defined(pl_btr_rel) && defined(pl_btr)
# define pl_btr_rel pl_btr
#endif


#if !defined(pl_bts_lax) && defined(pl_bts)
# define pl_bts_lax pl_bts
#endif

#if !defined(pl_bts_acq) && defined(pl_bts)
# define pl_bts_acq pl_bts
#endif

#if !defined(pl_bts_rel) && defined(pl_bts)
# define pl_bts_rel pl_bts
#endif


#if !defined(pl_ldadd_lax) && defined(pl_ldadd)
# define pl_ldadd_lax pl_ldadd
#endif

#if !defined(pl_ldadd_acq) && defined(pl_ldadd)
# define pl_ldadd_acq pl_ldadd
#endif

#if !defined(pl_ldadd_rel) && defined(pl_ldadd)
# define pl_ldadd_rel pl_ldadd
#endif


#if !defined(pl_ldsub_lax) && defined(pl_ldsub)
# define pl_ldsub_lax pl_ldsub
#endif

#if !defined(pl_ldsub_acq) && defined(pl_ldsub)
# define pl_ldsub_acq pl_ldsub
#endif

#if !defined(pl_ldsub_rel) && defined(pl_ldsub)
# define pl_ldsub_rel pl_ldsub
#endif


#if !defined(pl_ldand_lax) && defined(pl_ldand)
# define pl_ldand_lax pl_ldand
#endif

#if !defined(pl_ldand_acq) && defined(pl_ldand)
# define pl_ldand_acq pl_ldand
#endif

#if !defined(pl_ldand_rel) && defined(pl_ldand)
# define pl_ldand_rel pl_ldand
#endif


#if !defined(pl_ldor_lax) && defined(pl_ldor)
# define pl_ldor_lax pl_ldor
#endif

#if !defined(pl_ldor_acq) && defined(pl_ldor)
# define pl_ldor_acq pl_ldor
#endif

#if !defined(pl_ldor_rel) && defined(pl_ldor)
# define pl_ldor_rel pl_ldor
#endif


#if !defined(pl_ldxor_lax) && defined(pl_ldxor)
# define pl_ldxor_lax pl_ldxor
#endif

#if !defined(pl_ldxor_acq) && defined(pl_ldxor)
# define pl_ldxor_acq pl_ldxor
#endif

#if !defined(pl_ldxor_rel) && defined(pl_ldxor)
# define pl_ldxor_rel pl_ldxor
#endif


#endif /* PL_ATOMIC_OPS_H */
