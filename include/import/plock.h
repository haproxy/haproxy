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
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

/* 64 bit */
#define PLOCK64_RL_1   0x0000000000000004ULL
#define PLOCK64_RL_2PL 0x00000000FFFFFFF8ULL
#define PLOCK64_RL_ANY 0x00000000FFFFFFFCULL
#define PLOCK64_SL_1   0x0000000100000000ULL
#define PLOCK64_SL_ANY 0x0000000300000000ULL
#define PLOCK64_WL_1   0x0000000400000000ULL
#define PLOCK64_WL_2PL 0xFFFFFFF800000000ULL
#define PLOCK64_WL_ANY 0xFFFFFFFC00000000ULL

/* 32 bit */
#define PLOCK32_RL_1   0x00000004
#define PLOCK32_RL_2PL 0x0000FFF8
#define PLOCK32_RL_ANY 0x0000FFFC
#define PLOCK32_SL_1   0x00010000
#define PLOCK32_SL_ANY 0x00030000
#define PLOCK32_WL_1   0x00040000
#define PLOCK32_WL_2PL 0xFFF80000
#define PLOCK32_WL_ANY 0xFFFC0000

/* dereferences <*p> as unsigned long without causing aliasing issues */
#define pl_deref_long(p) ({ volatile unsigned long *__pl_l = (unsigned long *)(p); *__pl_l; })

/* dereferences <*p> as unsigned int without causing aliasing issues */
#define pl_deref_int(p) ({ volatile unsigned int *__pl_i = (unsigned int *)(p); *__pl_i; })

/* This function waits for <lock> to release all bits covered by <mask>, and
 * enforces an exponential backoff using CPU pauses to limit the pollution to
 * the other threads' caches. The progression follows (1.5^N)-1, limited to
 * 16384 iterations, which is way sufficient even for very large numbers of
 * threads.
 */
__attribute__((unused,noinline,no_instrument_function))
static unsigned long pl_wait_unlock_long(const unsigned long *lock, const unsigned long mask)
{
	unsigned long ret;
	unsigned int m = 0;

	do {
		unsigned int loops = m;

#ifdef _POSIX_PRIORITY_SCHEDULING
		if (loops >= 65536) {
			sched_yield();
			loops -= 32768;
		}
#endif
		for (; loops >= 200; loops -= 10)
			pl_cpu_relax();

		for (; loops >= 1; loops--)
			pl_barrier();

		ret = pl_deref_long(lock);
		if (__builtin_expect(ret & mask, 0) == 0)
			break;

		/* the below produces an exponential growth with loops to lower
		 * values and still growing. This allows competing threads to
		 * wait different times once the threshold is reached.
		 */
		m = ((m + (m >> 1)) + 2) & 0x3ffff;
	} while (1);

	return ret;
}

/* This function waits for <lock> to release all bits covered by <mask>, and
 * enforces an exponential backoff using CPU pauses to limit the pollution to
 * the other threads' caches. The progression follows (2^N)-1, limited to 255
 * iterations, which is way sufficient even for very large numbers of threads.
 * The function slightly benefits from size optimization under gcc, but Clang
 * cannot do it, so it's not done here, as it doesn't make a big difference.
 */
__attribute__((unused,noinline,no_instrument_function))
static unsigned int pl_wait_unlock_int(const unsigned int *lock, const unsigned int mask)
{
	unsigned int ret;
	unsigned int m = 0;

	do {
		unsigned int loops = m;

#ifdef _POSIX_PRIORITY_SCHEDULING
		if (loops >= 65536) {
			sched_yield();
			loops -= 32768;
		}
#endif
		for (; loops >= 200; loops -= 10)
			pl_cpu_relax();

		for (; loops >= 1; loops--)
			pl_barrier();

		ret = pl_deref_int(lock);
		if (__builtin_expect(ret & mask, 0) == 0)
			break;

		/* the below produces an exponential growth with loops to lower
		 * values and still growing. This allows competing threads to
		 * wait different times once the threshold is reached.
		 */
		m = ((m + (m >> 1)) + 2) & 0x3ffff;
	} while (1);

	return ret;
}

/* This function waits for <lock> to change from value <prev> and returns the
 * new value. It enforces an exponential backoff using CPU pauses to limit the
 * pollution to the other threads' caches. The progression follows (2^N)-1,
 * limited to 255 iterations, which is way sufficient even for very large
 * numbers of threads. It is designed to be called after a first test which
 * retrieves the previous value, so it starts by waiting. The function slightly
 * benefits from size optimization under gcc, but Clang cannot do it, so it's
 * not done here, as it doesn't make a big difference.
 */
__attribute__((unused,noinline,no_instrument_function))
static unsigned long pl_wait_new_long(const unsigned long *lock, const unsigned long prev)
{
	unsigned char m = 0;
	unsigned long curr;

	do {
		unsigned char loops = m + 1;
		m = (m << 1) + 1;
		do {
			pl_cpu_relax();
		} while (__builtin_expect(--loops, 0));
		curr = pl_deref_long(lock);
	} while (__builtin_expect(curr == prev, 0));
	return curr;
}

/* This function waits for <lock> to change from value <prev> and returns the
 * new value. It enforces an exponential backoff using CPU pauses to limit the
 * pollution to the other threads' caches. The progression follows (2^N)-1,
 * limited to 255 iterations, which is way sufficient even for very large
 * numbers of threads. It is designed to be called after a first test which
 * retrieves the previous value, so it starts by waiting. The function slightly
 * benefits from size optimization under gcc, but Clang cannot do it, so it's
 * not done here, as it doesn't make a big difference.
 */
__attribute__((unused,noinline,no_instrument_function))
static unsigned int pl_wait_new_int(const unsigned int *lock, const unsigned int prev)
{
	unsigned char m = 0;
	unsigned int curr;

	do {
		unsigned char loops = m + 1;
		m = (m << 1) + 1;
		do {
			pl_cpu_relax();
		} while (__builtin_expect(--loops, 0));
		curr = pl_deref_int(lock);
	} while (__builtin_expect(curr == prev, 0));
	return curr;
}

/* request shared read access (R), return non-zero on success, otherwise 0 */
#define pl_try_r(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_WL_ANY;          \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_RL_1) & PLOCK64_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_WL_ANY;            \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_RL_1) & PLOCK32_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_r__(char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_r__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request shared read access (R) and wait for it. In order not to disturb a W
 * lock waiting for all readers to leave, we first check if a W lock is held
 * before trying to claim the R lock.
 */
#define pl_take_r(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_RL_1;                                 \
		register unsigned long __msk_r = PLOCK64_WL_ANY;                               \
		while (1) {                                                                    \
			if (__builtin_expect(pl_deref_long(__lk_r) & __msk_r, 0))              \
				pl_wait_unlock_long(__lk_r, __msk_r);                          \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_RL_1;                                  \
		register unsigned int __msk_r = PLOCK32_WL_ANY;                                \
		while (1) {                                                                    \
			if (__builtin_expect(pl_deref_int(__lk_r) & __msk_r, 0))               \
				pl_wait_unlock_int(__lk_r, __msk_r);                           \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_r__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_r__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release the read access (R) lock */
#define pl_drop_r(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_RL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_RL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_r__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_r__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* request a seek access (S), return non-zero on success, otherwise 0 */
#define pl_try_s(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long __pl_r = pl_deref_long(lock);                           \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1 | PLOCK64_RL_1) &                \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1 | PLOCK64_RL_1);                   \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int __pl_r = pl_deref_int(lock);                             \
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
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_s__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request a seek access (S) and wait for it. The lock is immediately claimed,
 * and only upon failure an exponential backoff is used. S locks rarely compete
 * with W locks so S will generally not disturb W. As the S lock may be used as
 * a spinlock, it's important to grab it as fast as possible.
 */
#define pl_take_s(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_SL_1 | PLOCK64_RL_1;                  \
		register unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		while (1) {                                                                    \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_long(__lk_r, __msk_r);                                  \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_SL_1 | PLOCK32_RL_1;                   \
		register unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		while (1) {                                                                    \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_int(__lk_r, __msk_r);                                   \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_s__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_s__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release the seek access (S) lock */
#define pl_drop_s(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_SL_1 + PLOCK64_RL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_SL_1 + PLOCK32_RL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_s__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_s__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* drop the S lock and go back to the R lock */
#define pl_stor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_SL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_SL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stor__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_stor__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* take the W lock under the S lock */
#define pl_stow(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long __pl_r = pl_xadd((lock), PLOCK64_WL_1);                 \
		while ((__pl_r & PLOCK64_RL_ANY) != PLOCK64_RL_1)                              \
			__pl_r = pl_deref_long(lock);                                          \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int __pl_r = pl_xadd((lock), PLOCK32_WL_1);                  \
		while ((__pl_r & PLOCK32_RL_ANY) != PLOCK32_RL_1)                              \
			__pl_r = pl_deref_int(lock);                                           \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stow__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_stow__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* drop the W lock and go back to the S lock */
#define pl_wtos(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtos__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_wtos__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* drop the W lock and go back to the R lock */
#define pl_wtor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtor__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_wtor__(__FILE__,__LINE__);          \
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
		register unsigned long __pl_r = pl_deref_long(lock);                           \
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
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int __pl_r = pl_deref_int(lock);                             \
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
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_w__(char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_w__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request a write access (W) and wait for it. The lock is immediately claimed,
 * and only upon failure an exponential backoff is used.
 */
#define pl_take_w(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1;   \
		register unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		register unsigned long __pl_r;                                                 \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (!__builtin_expect(__pl_r & __msk_r, 0))                            \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			__pl_r = pl_wait_unlock_long(__lk_r, __msk_r);                         \
		}                                                                              \
		/* wait for all other readers to leave */                                      \
		while (__builtin_expect(__pl_r, 0))                                            \
			__pl_r = pl_deref_long(__lk_r) - __set_r;                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1;    \
		register unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		register unsigned int __pl_r;                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (!__builtin_expect(__pl_r & __msk_r, 0))                            \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			__pl_r = pl_wait_unlock_int(__lk_r, __msk_r);                          \
		}                                                                              \
		/* wait for all other readers to leave */                                      \
		while (__builtin_expect(__pl_r, 0))                                            \
			__pl_r = pl_deref_int(__lk_r) - __set_r;                               \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_w__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_w__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* drop the write (W) lock entirely */
#define pl_drop_w(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);                      \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);                      \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_w__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_w__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* Try to upgrade from R to S, return non-zero on success, otherwise 0.
 * This lock will fail if S or W are already held. In case of failure to grab
 * the lock, it MUST NOT be retried without first dropping R, or it may never
 * complete due to S waiting for R to leave before upgrading to W.
 */
#define pl_try_rtos(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long __pl_r = pl_deref_long(lock);                           \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1) &                               \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int __pl_r = pl_deref_int(lock);                             \
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
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtos__(__FILE__,__LINE__);      \
		0;                                                                             \
	})                                                                                     \
)


/* Try to upgrade from R to W, return non-zero on success, otherwise 0.
 * This lock will fail if S or W are already held. In case of failure to grab
 * the lock, it MUST NOT be retried without first dropping R, or it may never
 * complete due to S waiting for R to leave before upgrading to W. It waits for
 * the last readers to leave.
 */
#define pl_try_rtow(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_SL_1;                  \
		register unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		register unsigned long __pl_r;                                                 \
		pl_barrier();                                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				if (pl_xadd(__lk_r, - __set_r))                                \
					break; /* the caller needs to drop the lock now */     \
				continue;  /* lock was released, try again */                  \
			}                                                                      \
			/* ok we're the only writer, wait for readers to leave */              \
			while (__builtin_expect(__pl_r, 0))                                    \
				__pl_r = pl_deref_long(__lk_r) - (PLOCK64_WL_1|PLOCK64_SL_1|PLOCK64_RL_1); \
			/* now return with __pl_r = 0 */                                       \
			break;                                                                 \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_SL_1;                   \
		register unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		register unsigned int __pl_r;                                                  \
		pl_barrier();                                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				if (pl_xadd(__lk_r, - __set_r))                                \
					break; /* the caller needs to drop the lock now */     \
				continue;  /* lock was released, try again */                  \
			}                                                                      \
			/* ok we're the only writer, wait for readers to leave */              \
			while (__builtin_expect(__pl_r, 0))                                    \
				__pl_r = pl_deref_int(__lk_r) - (PLOCK32_WL_1|PLOCK32_SL_1|PLOCK32_RL_1); \
			/* now return with __pl_r = 0 */                                       \
			break;                                                                 \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtow__(char *,int);                \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtow__(__FILE__,__LINE__);      \
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
		register unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;          \
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
		register unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;            \
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
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_a__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request atomic write access (A) and wait for it. See comments in pl_try_a() for
 * explanations.
 */
#define pl_take_a(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_WL_1;                                 \
		register unsigned long __msk_r = PLOCK64_SL_ANY;                               \
		register unsigned long __pl_r;                                                 \
		__pl_r = pl_xadd(__lk_r, __set_r);                                             \
		while (__builtin_expect(__pl_r & PLOCK64_RL_ANY, 0)) {                         \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				pl_sub(__lk_r, __set_r);                                       \
				pl_wait_unlock_long(__lk_r, __msk_r);                          \
				__pl_r = pl_xadd(__lk_r, __set_r);                             \
				continue;                                                      \
			}                                                                      \
			/* wait for all readers to leave or upgrade */                         \
			pl_cpu_relax(); pl_cpu_relax(); pl_cpu_relax();                        \
			__pl_r = pl_deref_long(lock);                                          \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_WL_1;                                  \
		register unsigned int __msk_r = PLOCK32_SL_ANY;                                \
		register unsigned int __pl_r;                                                  \
		__pl_r = pl_xadd(__lk_r, __set_r);                                             \
		while (__builtin_expect(__pl_r & PLOCK32_RL_ANY, 0)) {                         \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				pl_sub(__lk_r, __set_r);                                       \
				pl_wait_unlock_int(__lk_r, __msk_r);                           \
				__pl_r = pl_xadd(__lk_r, __set_r);                             \
				continue;                                                      \
			}                                                                      \
			/* wait for all readers to leave or upgrade */                         \
			pl_cpu_relax(); pl_cpu_relax(); pl_cpu_relax();                        \
			__pl_r = pl_deref_int(lock);                                           \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_a__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_a__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release atomic write access (A) lock */
#define pl_drop_a(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_a__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_a__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* Downgrade A to R. Inc(R), dec(W) then wait for W==0 */
#define pl_ator(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_RL_1 - PLOCK64_WL_1;                  \
		register unsigned long __msk_r = PLOCK64_WL_ANY;                               \
		register unsigned long __pl_r = pl_xadd(__lk_r, __set_r) + __set_r;            \
		while (__builtin_expect(__pl_r & __msk_r, 0)) {                                \
			__pl_r = pl_wait_unlock_long(__lk_r, __msk_r);                         \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_RL_1 - PLOCK32_WL_1;                   \
		register unsigned int __msk_r = PLOCK32_WL_ANY;                                \
		register unsigned int __pl_r = pl_xadd(__lk_r, __set_r) + __set_r;             \
		while (__builtin_expect(__pl_r & __msk_r, 0)) {                                \
			__pl_r = pl_wait_unlock_int(__lk_r, __msk_r);                          \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_ator__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_ator__(__FILE__,__LINE__);          \
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
		register unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;          \
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
		register unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;            \
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
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtoa__(__FILE__,__LINE__);      \
		0;                                                                             \
	})                                                                                     \
)


/*
 * The following operations cover the multiple writers model : U->R->J->C->A
 */


/* Upgrade R to J. Inc(W) then wait for R==W or S != 0 */
#define pl_rtoj(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __pl_r = pl_xadd(__lk_r, PLOCK64_WL_1) + PLOCK64_WL_1;  \
		register unsigned char __m = 0;                                                \
		while (!(__pl_r & PLOCK64_SL_ANY) &&                                           \
		       (__pl_r / PLOCK64_WL_1 != (__pl_r & PLOCK64_RL_ANY) / PLOCK64_RL_1)) {  \
			unsigned char __loops = __m + 1;                                       \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_long(__lk_r);                                        \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __pl_r = pl_xadd(__lk_r, PLOCK32_WL_1) + PLOCK32_WL_1;   \
		register unsigned char __m = 0;                                                \
		while (!(__pl_r & PLOCK32_SL_ANY) &&                                           \
		       (__pl_r / PLOCK32_WL_1 != (__pl_r & PLOCK32_RL_ANY) / PLOCK32_RL_1)) {  \
			unsigned char __loops = __m + 1;                                       \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_int(__lk_r);                                         \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_rtoj__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_rtoj__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* Upgrade J to C. Set S. Only one thread needs to do it though it's idempotent */
#define pl_jtoc(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __pl_r = pl_deref_long(__lk_r);                         \
		if (!(__pl_r & PLOCK64_SL_ANY))                                                \
			pl_or(__lk_r, PLOCK64_SL_1);                                           \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __pl_r = pl_deref_int(__lk_r);                           \
		if (!(__pl_r & PLOCK32_SL_ANY))                                                \
			pl_or(__lk_r, PLOCK32_SL_1);                                           \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_jtoc__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_jtoc__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* Upgrade R to C. Inc(W) then wait for R==W or S != 0 */
#define pl_rtoc(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __pl_r = pl_xadd(__lk_r, PLOCK64_WL_1) + PLOCK64_WL_1;  \
		register unsigned char __m = 0;                                                \
		while (__builtin_expect(!(__pl_r & PLOCK64_SL_ANY), 0)) {                      \
			unsigned char __loops;                                                 \
			if (__pl_r / PLOCK64_WL_1 == (__pl_r & PLOCK64_RL_ANY) / PLOCK64_RL_1) { \
				pl_or(__lk_r, PLOCK64_SL_1);                                   \
				break;                                                         \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_long(__lk_r);                                        \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __pl_r = pl_xadd(__lk_r, PLOCK32_WL_1) + PLOCK32_WL_1;   \
		register unsigned char __m = 0;                                                \
		while (__builtin_expect(!(__pl_r & PLOCK32_SL_ANY), 0)) {                      \
			unsigned char __loops;                                                 \
			if (__pl_r / PLOCK32_WL_1 == (__pl_r & PLOCK32_RL_ANY) / PLOCK32_RL_1) { \
				pl_or(__lk_r, PLOCK32_SL_1);                                   \
				break;                                                         \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_int(__lk_r);                                         \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_rtoj__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_rtoj__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* Drop the claim (C) lock : R--,W-- then clear S if !R */
#define pl_drop_c(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = - PLOCK64_RL_1 - PLOCK64_WL_1;                \
		register unsigned long __pl_r = pl_xadd(__lk_r, __set_r) + __set_r;            \
		if (!(__pl_r & PLOCK64_RL_ANY))                                                \
			pl_and(__lk_r, ~PLOCK64_SL_1);                                         \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = - PLOCK32_RL_1 - PLOCK32_WL_1;                 \
		register unsigned int __pl_r = pl_xadd(__lk_r, __set_r) + __set_r;             \
		if (!(__pl_r & PLOCK32_RL_ANY))                                                \
			pl_and(__lk_r, ~PLOCK32_SL_1);                                         \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_c__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_c__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* Upgrade C to A. R-- then wait for !S or clear S if !R */
#define pl_ctoa(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __pl_r = pl_xadd(__lk_r, -PLOCK64_RL_1) - PLOCK64_RL_1; \
		while (__pl_r & PLOCK64_SL_ANY) {                                              \
			if (!(__pl_r & PLOCK64_RL_ANY)) {                                      \
				pl_and(__lk_r, ~PLOCK64_SL_1);                                 \
				break;                                                         \
			}                                                                      \
			pl_cpu_relax();                                                        \
			pl_cpu_relax();                                                        \
			__pl_r = pl_deref_long(__lk_r);                                        \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __pl_r = pl_xadd(__lk_r, -PLOCK32_RL_1) - PLOCK32_RL_1;  \
		while (__pl_r & PLOCK32_SL_ANY) {                                              \
			if (!(__pl_r & PLOCK32_RL_ANY)) {                                      \
				pl_and(__lk_r, ~PLOCK32_SL_1);                                 \
				break;                                                         \
			}                                                                      \
			pl_cpu_relax();                                                        \
			pl_cpu_relax();                                                        \
			__pl_r = pl_deref_int(__lk_r);                                         \
		}                                                                              \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_ctoa__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_ctoa__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* downgrade the atomic write access lock (A) to join (J) */
#define pl_atoj(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_add(lock, PLOCK64_RL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_add(lock, PLOCK32_RL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_atoj__(char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_atoj__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* Returns non-zero if the thread calling it is the last writer, otherwise zero. It is
 * designed to be called before pl_drop_j(), pl_drop_c() or pl_drop_a() for operations
 * which need to be called only once.
 */
#define pl_last_writer(lock) (                                                                 \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		!(pl_deref_long(lock) & PLOCK64_WL_2PL);                                       \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		!(pl_deref_int(lock) & PLOCK32_WL_2PL);                                        \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_last_j__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_last_j__(__FILE__,__LINE__);        \
		0;                                                                             \
	})                                                                                     \
)

/* attempt to get an exclusive write access via the J lock and wait for it.
 * Only one thread may succeed in this operation. It will not conflict with
 * other users and will first wait for all writers to leave, then for all
 * readers to leave before starting. This offers a solution to obtain an
 * exclusive access to a shared resource in the R/J/C/A model. A concurrent
 * take_a() will wait for this one to finish first. Using a CAS instead of XADD
 * should make the operation converge slightly faster. Returns non-zero on
 * success otherwise 0.
 */
#define pl_try_j(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_RL_1;                  \
		register unsigned long __msk_r = PLOCK64_WL_ANY;                               \
		register unsigned long __pl_r;                                                 \
		register unsigned char __m;                                                    \
		pl_wait_unlock_long(__lk_r, __msk_r);                                          \
		__pl_r = pl_xadd(__lk_r, __set_r) + __set_r;                                   \
		/* wait for all other readers to leave */                                      \
		__m = 0;                                                                       \
		while (__builtin_expect(__pl_r & PLOCK64_RL_2PL, 0)) {                         \
			unsigned char __loops;                                                 \
			/* give up on other writers */                                         \
			if (__builtin_expect(__pl_r & PLOCK64_WL_2PL, 0)) {                    \
				pl_sub(__lk_r, __set_r);                                       \
				__pl_r = 0; /* failed to get the lock */                       \
				break;                                                         \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_long(__lk_r);                                        \
		}                                                                              \
		pl_barrier();                                                                  \
		__pl_r; /* return value, cannot be null on success */                          \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_RL_1;                   \
		register unsigned int __msk_r = PLOCK32_WL_ANY;                                \
		register unsigned int __pl_r;                                                  \
		register unsigned char __m;                                                    \
		pl_wait_unlock_int(__lk_r, __msk_r);                                           \
		__pl_r = pl_xadd(__lk_r, __set_r) + __set_r;                                   \
		/* wait for all other readers to leave */                                      \
		__m = 0;                                                                       \
		while (__builtin_expect(__pl_r & PLOCK32_RL_2PL, 0)) {                         \
			unsigned char __loops;                                                 \
			/* but rollback on other writers */                                    \
			if (__builtin_expect(__pl_r & PLOCK32_WL_2PL, 0)) {                    \
				pl_sub(__lk_r, __set_r);                                       \
				__pl_r = 0; /* failed to get the lock */                       \
				break;                                                         \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_int(__lk_r);                                         \
		}                                                                              \
		pl_barrier();                                                                  \
		__pl_r; /* return value, cannot be null on success */                          \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_j__(char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_j__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request an exclusive write access via the J lock and wait for it. Only one
 * thread may succeed in this operation. It will not conflict with other users
 * and will first wait for all writers to leave, then for all readers to leave
 * before starting. This offers a solution to obtain an exclusive access to a
 * shared resource in the R/J/C/A model. A concurrent take_a() will wait for
 * this one to finish first. Using a CAS instead of XADD should make the
 * operation converge slightly faster.
 */
#define pl_take_j(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__label__ __retry;                                                             \
		register unsigned long *__lk_r = (unsigned long *)(lock);                      \
		register unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_RL_1;                  \
		register unsigned long __msk_r = PLOCK64_WL_ANY;                               \
		register unsigned long __pl_r;                                                 \
		register unsigned char __m;                                                    \
	__retry:                                                                               \
		pl_wait_unlock_long(__lk_r, __msk_r);                                          \
		__pl_r = pl_xadd(__lk_r, __set_r) + __set_r;                                   \
		/* wait for all other readers to leave */                                      \
		__m = 0;                                                                       \
		while (__builtin_expect(__pl_r & PLOCK64_RL_2PL, 0)) {                         \
			unsigned char __loops;                                                 \
			/* but rollback on other writers */                                    \
			if (__builtin_expect(__pl_r & PLOCK64_WL_2PL, 0)) {                    \
				pl_sub(__lk_r, __set_r);                                       \
				goto __retry;                                                  \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_long(__lk_r);                                        \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__label__ __retry;                                                             \
		register unsigned int *__lk_r = (unsigned int *)(lock);                        \
		register unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_RL_1;                   \
		register unsigned int __msk_r = PLOCK32_WL_ANY;                                \
		register unsigned int __pl_r;                                                  \
		register unsigned char __m;                                                    \
	__retry:                                                                               \
		pl_wait_unlock_int(__lk_r, __msk_r);                                           \
		__pl_r = pl_xadd(__lk_r, __set_r) + __set_r;                                   \
		/* wait for all other readers to leave */                                      \
		__m = 0;                                                                       \
		while (__builtin_expect(__pl_r & PLOCK32_RL_2PL, 0)) {                         \
			unsigned char __loops;                                                 \
			/* but rollback on other writers */                                    \
			if (__builtin_expect(__pl_r & PLOCK32_WL_2PL, 0)) {                    \
				pl_sub(__lk_r, __set_r);                                       \
				goto __retry;                                                  \
			}                                                                      \
			__loops = __m + 1;                                                     \
			__m = (__m << 1) + 1;                                                  \
			do {                                                                   \
				pl_cpu_relax();                                                \
				pl_cpu_relax();                                                \
			} while (--__loops);                                                   \
			__pl_r = pl_deref_int(__lk_r);                                         \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_j__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_j__(__FILE__,__LINE__);        \
		0;                                                                             \
	})                                                                                     \
)

/* drop the join (J) lock entirely */
#define pl_drop_j(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_RL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_RL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_j__(char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_j__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/*
 * The part below is for Low Overhead R/W locks (LORW). These ones are not
 * upgradable and not necessarily fair but they try to be fast when uncontended
 * and to limit the cost and perturbation during contention. Writers always
 * have precedence over readers to preserve latency as much as possible.
 *
 * The principle is to offer a fast no-contention path and a limited total
 * number of writes for the contended path. Since R/W locks are expected to be
 * used in situations where there is a benefit in separating reads from writes,
 * it is expected that reads are common (typ >= 50%) and that there is often at
 * least one reader (otherwise a spinlock wouldn't be a problem). As such, a
 * reader will try to pass instantly, detect contention and immediately retract
 * and wait in the queue in case there is contention. A writer will first also
 * try to pass instantly, and if it fails due to pending readers, it will mark
 * that it's waiting so that readers stop entering. This will leave the writer
 * waiting as close as possible to the point of being granted access. New
 * writers will also notice this previous contention and will wait outside.
 * This means that a successful access for a reader or a writer requires a
 * single CAS, and a contended attempt will require one failed CAS and one
 * successful XADD for a reader, or an optional OR and a N+1 CAS for the
 * writer.
 *
 * A counter of shared users indicates the number of active readers, while a
 * (single-bit) counter of exclusive writers indicates whether the lock is
 * currently held for writes. This distinction also permits to use a single
 * function to release the lock if desired, since the exclusive bit indicates
 * the state of the caller of unlock(). The WRQ bit is cleared during the
 * unlock.
 *
 * Layout: (32/64 bit):
 *                      31           2   1     0
 *         +-----------+--------------+-----+-----+
 *         |           |     SHR      | WRQ | EXC |
 *         +-----------+--------------+-----+-----+
 *
 * In order to minimize operations, the WRQ bit is held during EXC so that the
 * write waiter that had to fight for EXC doesn't have to release WRQ during
 * its operations, and will just drop it along with EXC upon unlock.
 *
 * This means the following costs:
 *   reader:
 *      success: 1 CAS
 *      failure: 1 CAS + 1 XADD
 *      unlock:  1 SUB
 *   writer:
 *      success: 1 RD + 1 CAS
 *      failure: 1 RD + 1 CAS + 0/1 OR + N CAS
 *      unlock:  1 AND
 */

#define PLOCK_LORW_EXC_BIT    ((sizeof(long) == 8) ?  0 :  0)
#define PLOCK_LORW_EXC_SIZE   ((sizeof(long) == 8) ?  1 :  1)
#define PLOCK_LORW_EXC_BASE   (1UL << PLOCK_LORW_EXC_BIT)
#define PLOCK_LORW_EXC_MASK   (((1UL << PLOCK_LORW_EXC_SIZE) - 1UL) << PLOCK_LORW_EXC_BIT)

#define PLOCK_LORW_WRQ_BIT    ((sizeof(long) == 8) ?  1 :  1)
#define PLOCK_LORW_WRQ_SIZE   ((sizeof(long) == 8) ?  1 :  1)
#define PLOCK_LORW_WRQ_BASE   (1UL << PLOCK_LORW_WRQ_BIT)
#define PLOCK_LORW_WRQ_MASK   (((1UL << PLOCK_LORW_WRQ_SIZE) - 1UL) << PLOCK_LORW_WRQ_BIT)

#define PLOCK_LORW_SHR_BIT    ((sizeof(long) == 8) ?  2 :  2)
#define PLOCK_LORW_SHR_SIZE   ((sizeof(long) == 8) ? 30 : 30)
#define PLOCK_LORW_SHR_BASE   (1UL << PLOCK_LORW_SHR_BIT)
#define PLOCK_LORW_SHR_MASK   (((1UL << PLOCK_LORW_SHR_SIZE) - 1UL) << PLOCK_LORW_SHR_BIT)

__attribute__((unused,always_inline,no_instrument_function))
static inline void pl_lorw_rdlock(unsigned long *lock)
{
	unsigned long lk = 0;

	/* First, assume we're alone and try to get the read lock (fast path).
	 * It often works because read locks are often used on low-contention
	 * structs.
	 */
	lk = pl_cmpxchg(lock, 0, PLOCK_LORW_SHR_BASE);
	if (!lk)
		return;

	/* so we were not alone, make sure there's no writer waiting for the
	 * lock to be empty of visitors.
	 */
	if (lk & PLOCK_LORW_WRQ_MASK)
		lk = pl_wait_unlock_long(lock, PLOCK_LORW_WRQ_MASK);

	/* count us as visitor among others */
	lk = pl_xadd(lock, PLOCK_LORW_SHR_BASE);

	/* wait for end of exclusive access if any */
	if (lk & PLOCK_LORW_EXC_MASK)
		lk = pl_wait_unlock_long(lock, PLOCK_LORW_EXC_MASK);
}


__attribute__((unused,always_inline,no_instrument_function))
static inline void pl_lorw_wrlock(unsigned long *lock)
{
	unsigned long lk = 0;
	unsigned long old = 0;

	/* first, make sure another writer is not already blocked waiting for
	 * readers to leave. Note that tests have shown that it can be even
	 * faster to avoid the first check and to unconditionally wait.
	 */
	lk = pl_deref_long(lock);
	if (__builtin_expect(lk & PLOCK_LORW_WRQ_MASK, 1))
		lk = pl_wait_unlock_long(lock, PLOCK_LORW_WRQ_MASK);

	do {
		/* let's check for the two sources of contention at once */

		if (__builtin_expect(lk & (PLOCK_LORW_SHR_MASK | PLOCK_LORW_EXC_MASK), 1)) {
			/* check if there are still readers coming. If so, close the door and
			 * wait for them to leave.
			 */
			if (lk & PLOCK_LORW_SHR_MASK) {
				/* note below, an OR is significantly cheaper than BTS or XADD */
				if (!(lk & PLOCK_LORW_WRQ_MASK))
					pl_or(lock, PLOCK_LORW_WRQ_BASE);
				lk = pl_wait_unlock_long(lock, PLOCK_LORW_SHR_MASK);
			}

			/* And also wait for a previous writer to finish. */
			if (lk & PLOCK_LORW_EXC_MASK)
				lk = pl_wait_unlock_long(lock, PLOCK_LORW_EXC_MASK);
		}

		/* A fresh new reader may appear right now if there were none
		 * above and we didn't close the door.
		 */
		old = lk & ~PLOCK_LORW_SHR_MASK & ~PLOCK_LORW_EXC_MASK;
		lk = pl_cmpxchg(lock, old, old | PLOCK_LORW_EXC_BASE);
	} while (lk != old);

	/* done, not waiting anymore, the WRQ bit if any, will be dropped by the
	 * unlock
	 */
}


__attribute__((unused,always_inline,no_instrument_function))
static inline void pl_lorw_rdunlock(unsigned long *lock)
{
	pl_sub(lock, PLOCK_LORW_SHR_BASE);
}

__attribute__((unused,always_inline,no_instrument_function))
static inline void pl_lorw_wrunlock(unsigned long *lock)
{
	pl_and(lock, ~(PLOCK_LORW_WRQ_MASK | PLOCK_LORW_EXC_MASK));
}

__attribute__((unused,always_inline,no_instrument_function))
static inline void pl_lorw_unlock(unsigned long *lock)
{
	if (pl_deref_long(lock) & PLOCK_LORW_EXC_MASK)
		pl_lorw_wrunlock(lock);
	else
		pl_lorw_rdunlock(lock);
}
