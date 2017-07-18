/* plock - progressive locks
 *
 * Copyright (C) 2012-2017 Willy Tarreau <w@1wt.eu>
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

#include "atomic-ops.h"

/* 64 bit */
#define PLOCK64_RL_1   0x0000000000000004ULL
#define PLOCK64_RL_ANY 0x00000000FFFFFFFCULL
#define PLOCK64_SL_1   0x0000000100000000ULL
#define PLOCK64_SL_ANY 0x0000000300000000ULL
#define PLOCK64_WL_1   0x0000000400000000ULL
#define PLOCK64_WL_ANY 0xFFFFFFFC00000000ULL

/* 32 bit */
#define PLOCK32_RL_1   0x00000004
#define PLOCK32_RL_ANY 0x0000FFFC
#define PLOCK32_SL_1   0x00010000
#define PLOCK32_SL_ANY 0x00030000
#define PLOCK32_WL_1   0x00040000
#define PLOCK32_WL_ANY 0xFFFC0000

/* dereferences <*p> as unsigned long without causing aliasing issues */
#define pl_deref_long(p) ({ volatile unsigned long *__pl_l = (void *)(p); *__pl_l; })

/* dereferences <*p> as unsigned int without causing aliasing issues */
#define pl_deref_int(p) ({ volatile unsigned int *__pl_i = (void *)(p); *__pl_i; })

/* request shared read access (R), return non-zero on success, otherwise 0 */
#define pl_try_r(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_WL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_RL_1) & PLOCK64_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_WL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_RL_1) & PLOCK32_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_r__(char *,int);                   \
		__unsupported_argument_size_for_pl_try_r__(__FILE__,__LINE__);                 \
		0;                                                                             \
	})                                                                                     \
)

/* request shared read access (R) and wait for it */
#define pl_take_r(lock)                                                                        \
	do {                                                                                   \
		while (__builtin_expect(pl_try_r(lock), 1) == 0)                               \
		       pl_cpu_relax();                                                         \
	} while (0)

/* release the read access (R) lock */
#define pl_drop_r(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_RL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_RL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_r__(char *,int);                  \
		__unsupported_argument_size_for_pl_drop_r__(__FILE__,__LINE__);                \
	})                                                                                     \
)

/* request a seek access (S), return non-zero on success, otherwise 0 */
#define pl_try_s(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1 | PLOCK64_RL_1) &                \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1 | PLOCK64_RL_1);                   \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_SL_1 | PLOCK32_RL_1) &                \
			      (PLOCK32_WL_ANY | PLOCK32_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_SL_1 | PLOCK32_RL_1);                   \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_s__(char *,int);                   \
		__unsupported_argument_size_for_pl_try_s__(__FILE__,__LINE__);                 \
		0;                                                                             \
	})                                                                                     \
)

/* request a seek access (S) and wait for it */
#define pl_take_s(lock)                                                                        \
	do {				                                                       \
		while (__builtin_expect(pl_try_s(lock), 0) == 0)                               \
		       pl_cpu_relax();                                                         \
	} while (0)

/* release the seek access (S) lock */
#define pl_drop_s(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_SL_1 + PLOCK64_RL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_SL_1 + PLOCK32_RL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_s__(char *,int);                  \
		__unsupported_argument_size_for_pl_drop_s__(__FILE__,__LINE__);                \
	})                                                                                     \
)

/* drop the S lock and go back to the R lock */
#define pl_stor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_SL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_SL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stor__(char *,int);                    \
		__unsupported_argument_size_for_pl_stor__(__FILE__,__LINE__);                  \
	})                                                                                     \
)

/* take the W lock under the S lock */
#define pl_stow(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_xadd((lock), PLOCK64_WL_1);                          \
		pl_barrier();                                                                  \
		while ((__pl_r & PLOCK64_RL_ANY) != PLOCK64_RL_1)                              \
			__pl_r = pl_deref_long(lock);                                          \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_xadd((lock), PLOCK32_WL_1);                           \
		pl_barrier();                                                                  \
		while ((__pl_r & PLOCK32_RL_ANY) != PLOCK32_RL_1)                              \
			__pl_r = pl_deref_int(lock);                                           \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stow__(char *,int);                    \
		__unsupported_argument_size_for_pl_stow__(__FILE__,__LINE__);                  \
	})                                                                                     \
)

/* drop the W lock and go back to the S lock */
#define pl_wtos(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtos__(char *,int);                    \
		__unsupported_argument_size_for_pl_wtos__(__FILE__,__LINE__);                  \
	})                                                                                     \
)

/* drop the W lock and go back to the R lock */
#define pl_wtor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtor__(char *,int);                    \
		__unsupported_argument_size_for_pl_wtor__(__FILE__,__LINE__);                  \
	})                                                                                     \
)

/* request a write access (W), return non-zero on success, otherwise 0.
 *
 * Below there is something important : by taking both W and S, we will cause
 * an overflow of W at 4/5 of the maximum value that can be stored into W due
 * to the fact that S is 2 bits, so we're effectively adding 5 to the word
 * composed by W:S. But for all words multiple of 4 bits, the maximum value is
 * multiple of 15 thus of 5. So the largest value we can store with all bits
 * set to one will be met by adding 5, and then adding 5 again will place value
 * 1 in W and value 0 in S, so we never leave W with 0. Also, even upon such an
 * overflow, there's no risk to confuse it with an atomic lock because R is not
 * null since it will not have overflown. For 32-bit locks, this situation
 * happens when exactly 13108 threads try to grab the lock at once, W=1, S=0
 * and R=13108. For 64-bit locks, it happens at 858993460 concurrent writers
 * where W=1, S=0 and R=858993460.
 */
#define pl_try_w(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);  \
			if (__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) { \
				/* a writer, seeker or atomic is present, let's leave */       \
				pl_sub((lock), PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);    \
				__pl_r &= (PLOCK64_WL_ANY | PLOCK64_SL_ANY); /* return value */\
			} else {                                                               \
				/* wait for all other readers to leave */                      \
				while (__pl_r)                                                 \
					__pl_r = pl_deref_long(lock) -                         \
						(PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);  \
					__pl_r = 0;                                            \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);  \
			if (__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) { \
				/* a writer, seeker or atomic is present, let's leave */       \
				pl_sub((lock), PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);    \
				__pl_r &= (PLOCK32_WL_ANY | PLOCK32_SL_ANY); /* return value */\
			} else {                                                               \
				/* wait for all other readers to leave */                      \
				while (__pl_r)                                                 \
					__pl_r = pl_deref_int(lock) -                          \
						(PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);  \
					__pl_r = 0;                                            \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_w__(char *,int);                   \
		__unsupported_argument_size_for_pl_try_w__(__FILE__,__LINE__);                 \
		0;                                                                             \
	})                                                                                     \
)

/* request a seek access (W) and wait for it */
#define pl_take_w(lock)                                                                        \
	do {				                                                       \
		while (__builtin_expect(pl_try_w(lock), 0) == 0)                               \
		       pl_cpu_relax();                                                         \
	} while (0)

/* drop the write (W) lock entirely */
#define pl_drop_w(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);                      \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);                      \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_w__(char *,int);                  \
		__unsupported_argument_size_for_pl_drop_w__(__FILE__,__LINE__);                \
	})                                                                                     \
)

/* Try to upgrade from R to S, return non-zero on success, otherwise 0.
 * This lock will fail if S or W are already held. In case of failure to grab
 * the lock, it MUST NOT be retried without first dropping R, or it may never
 * complete due to S waiting for R to leave before upgrading to W.
 */
#define pl_try_rtos(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1) &                               \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_SL_1) &                               \
			      (PLOCK32_WL_ANY | PLOCK32_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_SL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtos__(char *,int);                \
		__unsupported_argument_size_for_pl_try_rtos__(__FILE__,__LINE__);              \
		0;                                                                             \
	})                                                                                     \
)


/* request atomic write access (A), return non-zero on success, otherwise 0.
 * It's a bit tricky as we only use the W bits for this and want to distinguish
 * between other atomic users and regular lock users. We have to give up if an
 * S lock appears. It's possible that such a lock stays hidden in the W bits
 * after an overflow, but in this case R is still held, ensuring we stay in the
 * loop until we discover the conflict. The lock only return successfully if all
 * readers are gone (or converted to A).
 */
#define pl_try_a(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1);                                \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK64_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK64_WL_1);                          \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK64_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_long(lock);                                  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1);                                \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK32_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK32_WL_1);                          \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK32_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_int(lock);                                   \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_a__(char *,int);                   \
		__unsupported_argument_size_for_pl_try_a__(__FILE__,__LINE__);                 \
		0;                                                                             \
	})                                                                                     \
)

/* request atomic write access (A) and wait for it */
#define pl_take_a(lock)                                                                        \
	do {				                                                       \
		while (__builtin_expect(pl_try_a(lock), 1) == 0)                               \
		       pl_cpu_relax();                                                         \
	} while (0)

/* release atomic write access (A) lock */
#define pl_drop_a(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_a__(char *,int);                  \
		__unsupported_argument_size_for_pl_drop_a__(__FILE__,__LINE__);                \
	})                                                                                     \
)

/* Try to upgrade from R to A, return non-zero on success, otherwise 0.
 * This lock will fail if S is held or appears while waiting (typically due to
 * a previous grab that was disguised as a W due to an overflow). In case of
 * failure to grab the lock, it MUST NOT be retried without first dropping R,
 * or it may never complete due to S waiting for R to leave before upgrading
 * to W. The lock succeeds once there's no more R (ie all of them have either
 * completed or were turned to A).
 */
#define pl_try_rtoa(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1 - PLOCK64_RL_1);                 \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK64_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK64_WL_1 - PLOCK64_RL_1);           \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK64_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_long(lock);                                  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1 - PLOCK32_RL_1);                 \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK32_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK32_WL_1 - PLOCK32_RL_1);           \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK32_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_int(lock);                                   \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtoa__(char *,int);                \
		__unsupported_argument_size_for_pl_try_rtoa__(__FILE__,__LINE__);              \
		0;                                                                             \
	})                                                                                     \
)
