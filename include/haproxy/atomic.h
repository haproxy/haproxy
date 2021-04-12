/*
 * include/haproxy/atomic.h
 * Macros and inline functions for thread-safe atomic operations.
 *
 * Copyright (C) 2017 Christopher Faulet - cfaulet@haproxy.com
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_ATOMIC_H
#define _HAPROXY_ATOMIC_H

#include <string.h>

/* A few notes for the macros and functions here:
 *  - this file is painful to edit, most operations exist in 3 variants,
 *    no-thread, threads with gcc<4.7, threads with gcc>=4.7. Be careful when
 *    modifying it not to break any of them.
 *
 *  - macros named HA_ATOMIC_* are or use in the general case, they contain the
 *    required memory barriers to guarantee sequential consistency
 *
 *  - macros named _HA_ATOMIC_* are the same but without the memory barriers,
 *    so they may only be used if followed by other HA_ATOMIC_* or within a
 *    sequence of _HA_ATOMIC_* terminated by a store barrier, or when there is
 *    no data dependency (e.g. updating a counter). Not all of them are
 *    implemented, in which case fallbacks to the safe ones are provided. In
 *    case of doubt, don't use them and use the generic ones instead.
 *
 *  - the __ha_atomic_* barriers are for use around _HA_ATOMIC_* operations.
 *    Some architectures make them useless and they will automatically be
 *    dropped in such a case. Don't use them outside of this use case.
 *
 *  - in general, the more underscores you find in front of a function or macro
 *    name, the riskier it is to use. Barriers are among them because validating
 *    their usage is not trivial at all and it's often safer to fall back to
 *    more generic behaviors.
 *
 * There is also a compiler barrier (__ha_compiler_barrier) which is eliminated
 * when threads are disabled. We currently don't have a permanent compiler
 * barrier to prevent the compiler from reordering signal-sensitive code for
 * example.
 */


#ifndef USE_THREAD

/* Threads are DISABLED, atomic ops are also not used. Note that these MUST
 * NOT be used for inter-process synchronization nor signal-safe variable
 * manipulations which might occur without threads, as they are not atomic.
 */

#define HA_ATOMIC_LOAD(val)          *(val)
#define HA_ATOMIC_STORE(val, new)    ({*(val) = new;})

#define HA_ATOMIC_XCHG(val, new)					\
	({								\
		typeof(*(val)) __old_xchg = *(val);			\
		*(val) = new;						\
		__old_xchg;						\
	})

#define HA_ATOMIC_AND(val, flags)    do { *(val) &= (flags);} while (0)
#define HA_ATOMIC_OR(val, flags)     do { *(val) |= (flags);} while (0)
#define HA_ATOMIC_ADD(val, i)        do { *(val) += (i);} while (0)
#define HA_ATOMIC_SUB(val, i)        do { *(val) -= (i);} while (0)
#define HA_ATOMIC_INC(val)           do { *(val) += 1;} while (0)
#define HA_ATOMIC_DEC(val)           do { *(val) -= 1;} while (0)

#define HA_ATOMIC_AND_FETCH(val, flags) ({ *(val) &= (flags); })
#define HA_ATOMIC_OR_FETCH(val, flags)  ({ *(val) |= (flags); })
#define HA_ATOMIC_ADD_FETCH(val, i)     ({ *(val) += (i); })
#define HA_ATOMIC_SUB_FETCH(val, i)     ({ *(val) -= (i); })

#define HA_ATOMIC_FETCH_AND(val, i)					\
	({								\
		typeof((val)) __p_val = (val);				\
		typeof(*(val)) __old_val = *__p_val;			\
		*__p_val &= (i);					\
		__old_val;						\
	})

#define HA_ATOMIC_FETCH_OR(val, i)					\
	({								\
		typeof((val)) __p_val = (val);				\
		typeof(*(val)) __old_val = *__p_val;			\
		*__p_val |= (i);					\
		__old_val;						\
	})

#define HA_ATOMIC_FETCH_ADD(val, i)					\
	({								\
		typeof((val)) __p_val = (val);				\
		typeof(*(val)) __old_val = *__p_val;			\
		*__p_val += (i);					\
		__old_val;						\
	})

#define HA_ATOMIC_FETCH_SUB(val, i)					\
	({								\
		typeof((val)) __p_val = (val);				\
		typeof(*(val)) __old_val = *__p_val;			\
		*__p_val -= (i);					\
		__old_val;						\
	})

#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof((val)) __p_bts = (val);				\
		typeof(*__p_bts)  __b_bts = (1UL << (bit));		\
		typeof(*__p_bts)  __t_bts = *__p_bts & __b_bts;		\
		if (!__t_bts)						\
			*__p_bts |= __b_bts;				\
		__t_bts;						\
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof((val)) __p_btr = (val);				\
		typeof(*__p_btr)  __b_btr = (1UL << (bit));		\
		typeof(*__p_btr)  __t_btr = *__p_btr & __b_btr;		\
		if (__t_btr)						\
			*__p_btr &= ~__b_btr;				\
		__t_btr;						\
	})

#define HA_ATOMIC_CAS(val, old, new)					\
	({								\
		typeof(val) _v = (val);					\
		typeof(old) _o = (old);					\
		(*_v == *_o) ? ((*_v = (new)), 1) : ((*_o = *_v), 0);	\
	})

/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n)					\
	({								\
		long *_v = (long*)(val);				\
		long *_o = (long*)(o);					\
		long *_n = (long*)(n);					\
		long _v0 = _v[0], _v1 = _v[1];				\
		(_v0 == _o[0] && _v1 == _o[1]) ?			\
			(_v[0] = _n[0], _v[1] = _n[1], 1) :		\
			(_o[0] = _v0,   _o[1] = _v1,   0);		\
	})

#define HA_ATOMIC_UPDATE_MAX(val, new)					\
	({								\
		typeof(val) __val = (val);				\
		typeof(*(val)) __new_max = (new);			\
									\
		if (*__val < __new_max)					\
			*__val = __new_max;				\
		*__val;							\
	})

#define HA_ATOMIC_UPDATE_MIN(val, new)					\
	({								\
		typeof(val) __val = (val);                              \
		typeof(*(val)) __new_min = (new);			\
									\
		if (*__val > __new_min)					\
			*__val = __new_min;				\
		*__val;							\
	})

/* various barriers */
#define __ha_barrier_atomic_load()  do { } while (0)
#define __ha_barrier_atomic_store() do { } while (0)
#define __ha_barrier_atomic_full()  do { } while (0)
#define __ha_barrier_load()         do { } while (0)
#define __ha_barrier_store()        do { } while (0)
#define __ha_barrier_full()         do { } while (0)
#define __ha_compiler_barrier()     do { } while (0)
#define __ha_cpu_relax()            ({ 1; })

#else /* !USE_THREAD */

/* Threads are ENABLED, all atomic ops are made thread-safe. By extension they
 * can also be used for inter-process synchronization but one must verify that
 * the code still builds with threads disabled.
 */

#if defined(__GNUC__) && (__GNUC__ < 4 || __GNUC__ == 4 && __GNUC_MINOR__ < 7) && !defined(__clang__)
/* gcc < 4.7 */

#define HA_ATOMIC_LOAD(val)						\
        ({								\
	        typeof(*(val)) ret;					\
		__sync_synchronize();					\
		ret = *(volatile typeof(val))val;			\
		__sync_synchronize();					\
		ret;							\
	})

#define HA_ATOMIC_STORE(val, new)					\
	({								\
		typeof((val)) __val_store = (val);			\
		typeof(*(val)) __old_store;				\
		typeof((new)) __new_store = (new);			\
		do { __old_store = *__val_store;			\
		} while (!__sync_bool_compare_and_swap(__val_store, __old_store, __new_store)); \
	})

#define HA_ATOMIC_XCHG(val, new)					\
	({								\
		typeof((val)) __val_xchg = (val);			\
		typeof(*(val)) __old_xchg;				\
		typeof((new)) __new_xchg = (new);			\
		do { __old_xchg = *__val_xchg;				\
		} while (!__sync_bool_compare_and_swap(__val_xchg, __old_xchg, __new_xchg)); \
		__old_xchg;						\
	})

#define HA_ATOMIC_AND(val, flags)    do { __sync_and_and_fetch(val, flags); } while (0)
#define HA_ATOMIC_OR(val, flags)     do { __sync_or_and_fetch(val,  flags); } while (0)
#define HA_ATOMIC_ADD(val, i)        do { __sync_add_and_fetch(val, i); } while (0)
#define HA_ATOMIC_SUB(val, i)        do { __sync_sub_and_fetch(val, i); } while (0)
#define HA_ATOMIC_INC(val)           do { __sync_add_and_fetch(val, 1); } while (0)
#define HA_ATOMIC_DEC(val)           do { __sync_sub_and_fetch(val, 1); } while (0)

#define HA_ATOMIC_AND_FETCH(val, flags) __sync_and_and_fetch(val, flags)
#define HA_ATOMIC_OR_FETCH(val, flags)  __sync_or_and_fetch(val,  flags)
#define HA_ATOMIC_ADD_FETCH(val, i)     __sync_add_and_fetch(val, i)
#define HA_ATOMIC_SUB_FETCH(val, i)     __sync_sub_and_fetch(val, i)

#define HA_ATOMIC_FETCH_AND(val, flags) __sync_fetch_and_and(val, flags)
#define HA_ATOMIC_FETCH_OR(val, flags)  __sync_fetch_and_or(val,  flags)
#define HA_ATOMIC_FETCH_ADD(val, i)     __sync_fetch_and_add(val, i)
#define HA_ATOMIC_FETCH_SUB(val, i)     __sync_fetch_and_sub(val, i)

#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof(*(val)) __b_bts = (1UL << (bit));		\
		__sync_fetch_and_or((val), __b_bts) & __b_bts;		\
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof(*(val)) __b_btr = (1UL << (bit));		\
		__sync_fetch_and_and((val), ~__b_btr) & __b_btr;	\
	})

/* the CAS is a bit complicated. The older API doesn't support returning the
 * value and the swap's result at the same time. So here we take what looks
 * like the safest route, consisting in using the boolean version guaranteeing
 * that the operation was performed or not, and we snoop a previous value. If
 * the compare succeeds, we return. If it fails, we return the previous value,
 * but only if it differs from the expected one. If it's the same it's a race
 * thus we try again to avoid confusing a possibly sensitive caller.
 */
#define HA_ATOMIC_CAS(val, old, new)					\
	({								\
		typeof((val)) __val_cas = (val);			\
		typeof((old)) __oldp_cas = (old);			\
		typeof(*(old)) __oldv_cas;				\
		typeof((new)) __new_cas = (new);			\
		int __ret_cas;						\
		do {							\
			__oldv_cas = *__val_cas;			\
			__ret_cas = __sync_bool_compare_and_swap(__val_cas, *__oldp_cas, __new_cas); \
		} while (!__ret_cas && *__oldp_cas == __oldv_cas);	\
		if (!__ret_cas)						\
			*__oldp_cas = __oldv_cas;			\
		__ret_cas;						\
	})

/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n) __ha_cas_dw(val, o, n)

#define HA_ATOMIC_UPDATE_MAX(val, new)					\
	({								\
		typeof(val) __val = (val);				\
		typeof(*(val)) __old_max = *__val;			\
		typeof(*(val)) __new_max = (new);			\
									\
		while (__old_max < __new_max &&				\
		       !HA_ATOMIC_CAS(__val, &__old_max, __new_max));	\
		*__val;							\
	})

#define HA_ATOMIC_UPDATE_MIN(val, new)					\
	({								\
		typeof(val) __val = (val);				\
		typeof(*(val)) __old_min = *__val;			\
		typeof(*(val)) __new_min = (new);			\
									\
		while (__old_min > __new_min &&				\
		       !HA_ATOMIC_CAS(__val, &__old_min, __new_min));	\
		*__val;							\
	})

#else /* gcc */

/* gcc >= 4.7 or clang */

#define HA_ATOMIC_STORE(val, new)    __atomic_store_n(val, new, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_LOAD(val)          __atomic_load_n(val, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_XCHG(val, new)     __atomic_exchange_n(val, new, __ATOMIC_SEQ_CST)

#define HA_ATOMIC_AND(val, flags)    do { __atomic_and_fetch(val, flags, __ATOMIC_SEQ_CST); } while (0)
#define HA_ATOMIC_OR(val, flags)     do { __atomic_or_fetch(val,  flags, __ATOMIC_SEQ_CST); } while (0)
#define HA_ATOMIC_ADD(val, i)        do { __atomic_add_fetch(val, i, __ATOMIC_SEQ_CST); } while (0)
#define HA_ATOMIC_SUB(val, i)        do { __atomic_sub_fetch(val, i, __ATOMIC_SEQ_CST); } while (0)
#define HA_ATOMIC_INC(val)           do { __atomic_add_fetch(val, 1, __ATOMIC_SEQ_CST); } while (0)
#define HA_ATOMIC_DEC(val)           do { __atomic_sub_fetch(val, 1, __ATOMIC_SEQ_CST); } while (0)

#define HA_ATOMIC_AND_FETCH(val, flags) __atomic_and_fetch(val, flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_OR_FETCH(val, flags)  __atomic_or_fetch(val,  flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_ADD_FETCH(val, i)     __atomic_add_fetch(val, i, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_SUB_FETCH(val, i)     __atomic_sub_fetch(val, i, __ATOMIC_SEQ_CST)

#define HA_ATOMIC_FETCH_AND(val, flags) __atomic_fetch_and(val, flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_FETCH_OR(val, flags)  __atomic_fetch_or(val,  flags, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_FETCH_ADD(val, i)     __atomic_fetch_add(val, i, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_FETCH_SUB(val, i)     __atomic_fetch_sub(val, i, __ATOMIC_SEQ_CST)

#if defined(__GCC_ASM_FLAG_OUTPUTS__) && (defined(__i386__) || defined (__x86_64__))
#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		unsigned char __ret;					\
		if (sizeof(long) == 8 && sizeof(*(val)) == 8) {		\
			asm volatile("lock btsq %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned long)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 4) {			\
			asm volatile("lock btsl %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned int)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 2) {			\
			asm volatile("lock btsw %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned short)(bit))	\
				     : "cc");				\
		} else {						\
			typeof(*(val)) __b_bts = (1UL << (bit));	\
			__ret = !!(__atomic_fetch_or((val), __b_bts, __ATOMIC_SEQ_CST) & __b_bts); \
		}							\
		__ret;							\
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		unsigned char __ret;					\
		if (sizeof(long) == 8 && sizeof(*(val)) == 8) {		\
			asm volatile("lock btrq %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned long)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 4) {			\
			asm volatile("lock btrl %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned int)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 2) {			\
			asm volatile("lock btrw %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned short)(bit))	\
				     : "cc");				\
		} else {						\
			typeof(*(val)) __b_bts = (1UL << (bit));	\
			__ret = !!(__atomic_fetch_and((val), ~__b_bts, __ATOMIC_SEQ_CST) & __b_bts); \
		}							\
		__ret;							\
	})

#else // not x86 or !__GCC_ASM_FLAG_OUTPUTS__

#define HA_ATOMIC_BTS(val, bit)						\
	({								\
		typeof(*(val)) __b_bts = (1UL << (bit));		\
		__atomic_fetch_or((val), __b_bts, __ATOMIC_SEQ_CST) & __b_bts; \
	})

#define HA_ATOMIC_BTR(val, bit)						\
	({								\
		typeof(*(val)) __b_btr = (1UL << (bit));		\
		__atomic_fetch_and((val), ~__b_btr, __ATOMIC_SEQ_CST) & __b_btr; \
	})

#endif // x86 || __GCC_ASM_FLAG_OUTPUTS__

#define HA_ATOMIC_CAS(val, old, new) __atomic_compare_exchange_n(val, old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

/* warning, n is a pointer to the double value for dwcas */
#define HA_ATOMIC_DWCAS(val, o, n)   __ha_cas_dw(val, o, n)

#define HA_ATOMIC_UPDATE_MAX(val, new)					\
	({								\
		typeof(val) __val = (val);				\
		typeof(*(val)) __old_max = *__val;			\
		typeof(*(val)) __new_max = (new);			\
									\
		while (__old_max < __new_max &&				\
		       !HA_ATOMIC_CAS(__val, &__old_max, __new_max));	\
		*__val;							\
	})

#define HA_ATOMIC_UPDATE_MIN(val, new)					\
	({								\
		typeof(val) __val = (val);				\
		typeof(*(val)) __old_min = *__val;			\
		typeof(*(val)) __new_min = (new);			\
									\
		while (__old_min > __new_min &&				\
		       !HA_ATOMIC_CAS(__val, &__old_min, __new_min));	\
		*__val;							\
	})

/* Modern compilers provide variants that don't generate any memory barrier.
 * If you're unsure how to deal with barriers, just use the HA_ATOMIC_* version,
 * that will always generate correct code.
 * Usually it's fine to use those when updating data that have no dependency,
 * ie updating a counter. Otherwise a barrier is required.
 */

#define _HA_ATOMIC_LOAD(val)          __atomic_load_n(val, __ATOMIC_RELAXED)
#define _HA_ATOMIC_STORE(val, new)    __atomic_store_n(val, new, __ATOMIC_RELAXED)
#define _HA_ATOMIC_XCHG(val, new)     __atomic_exchange_n(val, new, __ATOMIC_RELAXED)

#define _HA_ATOMIC_AND(val, flags)    do { __atomic_and_fetch(val, flags, __ATOMIC_RELAXED); } while (0)
#define _HA_ATOMIC_OR(val, flags)     do { __atomic_or_fetch(val,  flags, __ATOMIC_RELAXED); } while (0)
#define _HA_ATOMIC_ADD(val, i)        do { __atomic_add_fetch(val, i, __ATOMIC_RELAXED); } while (0)
#define _HA_ATOMIC_SUB(val, i)        do { __atomic_sub_fetch(val, i, __ATOMIC_RELAXED); } while (0)
#define _HA_ATOMIC_INC(val)           do { __atomic_add_fetch(val, 1, __ATOMIC_RELAXED); } while (0)
#define _HA_ATOMIC_DEC(val)           do { __atomic_sub_fetch(val, 1, __ATOMIC_RELAXED); } while (0)

#define _HA_ATOMIC_AND_FETCH(val, flags) __atomic_and_fetch(val, flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_OR_FETCH(val, flags)  __atomic_or_fetch(val,  flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_ADD_FETCH(val, i)     __atomic_add_fetch(val, i, __ATOMIC_RELAXED)
#define _HA_ATOMIC_SUB_FETCH(val, i)     __atomic_sub_fetch(val, i, __ATOMIC_RELAXED)

#define _HA_ATOMIC_FETCH_AND(val, flags) __atomic_fetch_and(val, flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_FETCH_OR(val, flags)  __atomic_fetch_or(val,  flags, __ATOMIC_RELAXED)
#define _HA_ATOMIC_FETCH_ADD(val, i)     __atomic_fetch_add(val, i, __ATOMIC_RELAXED)
#define _HA_ATOMIC_FETCH_SUB(val, i)     __atomic_fetch_sub(val, i, __ATOMIC_RELAXED)

#if defined(__GCC_ASM_FLAG_OUTPUTS__) && (defined(__i386__) || defined (__x86_64__))
#define _HA_ATOMIC_BTS(val, bit)					\
	({								\
		unsigned char __ret;					\
		if (sizeof(long) == 8 && sizeof(*(val)) == 8) {		\
			asm volatile("lock btsq %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned long)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 4) {			\
			asm volatile("lock btsl %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned int)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 2) {			\
			asm volatile("lock btsw %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned short)(bit))	\
				     : "cc");				\
		} else {						\
			typeof(*(val)) __b_bts = (1UL << (bit));	\
			__ret = !!(__atomic_fetch_or((val), __b_bts, __ATOMIC_RELAXED) & __b_bts); \
		}							\
		__ret;							\
	})

#define _HA_ATOMIC_BTR(val, bit)					\
	({								\
		unsigned char __ret;					\
		if (sizeof(long) == 8 && sizeof(*(val)) == 8) {		\
			asm volatile("lock btrq %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned long)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 4) {			\
			asm volatile("lock btrl %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned int)(bit))	\
				     : "cc");				\
		} else if (sizeof(*(val)) == 2) {			\
			asm volatile("lock btrw %2, %0\n"		\
				     : "+m" (*(val)), "=@ccc"(__ret)	\
				     : "Ir" ((unsigned short)(bit))	\
				     : "cc");				\
		} else {						\
			typeof(*(val)) __b_bts = (1UL << (bit));	\
			__ret = !!(__atomic_fetch_and((val), ~__b_bts, __ATOMIC_RELAXED) & __b_bts); \
		}							\
		__ret;							\
	})

#else // not x86 or !__GCC_ASM_FLAG_OUTPUTS__

#define _HA_ATOMIC_BTS(val, bit)					\
	({								\
		typeof(*(val)) __b_bts = (1UL << (bit));		\
		__atomic_fetch_or((val), __b_bts, __ATOMIC_RELAXED) & __b_bts; \
	})

#define _HA_ATOMIC_BTR(val, bit)					\
	({								\
		typeof(*(val)) __b_btr = (1UL << (bit));		\
		__atomic_fetch_and((val), ~__b_btr, __ATOMIC_RELAXED) & __b_btr; \
	})
#endif

#define _HA_ATOMIC_CAS(val, old, new) __atomic_compare_exchange_n(val, old, new, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)
/* warning, n is a pointer to the double value for dwcas */
#define _HA_ATOMIC_DWCAS(val, o, n)   __ha_cas_dw(val, o, n)

#endif /* gcc >= 4.7 */

/* Here come a few architecture-specific double-word CAS and barrier
 * implementations.
 */

#ifdef __x86_64__

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("lfence" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("sfence" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("mfence" ::: "memory");
}

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using _HA_ATOMIC*
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("" ::: "memory");
}

static __inline int
__ha_cas_dw(void *target, void *compare, const void *set)
{
        char ret;

        __asm __volatile("lock cmpxchg16b %0; setz %3"
                          : "+m" (*(void **)target),
                            "=a" (((void **)compare)[0]),
                            "=d" (((void **)compare)[1]),
                            "=q" (ret)
                          : "a" (((void **)compare)[0]),
                            "d" (((void **)compare)[1]),
                            "b" (((const void **)set)[0]),
                            "c" (((const void **)set)[1])
                          : "memory", "cc");
        return (ret);
}

/* short-lived CPU relaxation */
#define __ha_cpu_relax() ({ asm volatile("rep;nop\n"); 1; })

#elif defined(__arm__) && (defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__))

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("dsb" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("dmb" ::: "memory");
}

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using _HA_ATOMIC*
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("dsb" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("dmb" ::: "memory");
}

static __inline int __ha_cas_dw(void *target, void *compare, const void *set)
{
	uint64_t previous;
	int tmp;

	__asm __volatile("1:"
	                 "ldrexd %0, [%4];"
			 "cmp %Q0, %Q2;"
			 "ittt eq;"
			 "cmpeq %R0, %R2;"
			 "strexdeq %1, %3, [%4];"
			 "cmpeq %1, #1;"
			 "beq 1b;"
			 : "=&r" (previous), "=&r" (tmp)
			 : "r" (*(uint64_t *)compare), "r" (*(uint64_t *)set), "r" (target)
			 : "memory", "cc");
	tmp = (previous == *(uint64_t *)compare);
	*(uint64_t *)compare = previous;
	return (tmp);
}

/* short-lived CPU relaxation */
#define __ha_cpu_relax() ({ asm volatile(""); 1; })

#elif defined (__aarch64__)

static __inline void
__ha_barrier_load(void)
{
	__asm __volatile("dmb ishld" ::: "memory");
}

static __inline void
__ha_barrier_store(void)
{
	__asm __volatile("dmb ishst" ::: "memory");
}

static __inline void
__ha_barrier_full(void)
{
	__asm __volatile("dmb ish" ::: "memory");
}

/* Use __ha_barrier_atomic* when you're trying to protect data that are
 * are modified using _HA_ATOMIC*
 */
static __inline void
__ha_barrier_atomic_load(void)
{
	__asm __volatile("dmb ishld" ::: "memory");
}

static __inline void
__ha_barrier_atomic_store(void)
{
	__asm __volatile("dmb ishst" ::: "memory");
}

static __inline void
__ha_barrier_atomic_full(void)
{
	__asm __volatile("dmb ish" ::: "memory");
}

/* short-lived CPU relaxation; this was shown to improve fairness on
 * modern ARMv8 cores such as Neoverse N1.
 */
#define __ha_cpu_relax() ({ asm volatile("isb" ::: "memory"); 1; })

#if defined(__ARM_FEATURE_ATOMICS) // ARMv8.1-A atomics

/* returns 0 on failure, non-zero on success */
static forceinline int __ha_cas_dw(void *target, void *compare, const void *set)
{
	/* There's no status set by the CASP instruction so we need to keep a
	 * copy of the original registers and compare them afterwards to detect
	 * if we could apply the change. In order to pass a pair, we simply map
	 * a register pair on a struct so that the compiler can emit register
	 * pairs that we can use thanks to the undocumented "%H" modifier
	 * mentioned on the link below:
	 *   https://patchwork.ozlabs.org/project/gcc/patch/59368A74.2060908@foss.arm.com/
	 */
	struct pair { uint64_t r[2]; };
	register struct pair bck = *(struct pair *)compare;
	register struct pair cmp asm("x0") = bck;
	register struct pair new asm("x2") = *(const struct pair*)set;
	int ret;

	__asm__ __volatile__("casp %0, %H0, %2, %H2, [%1]\n"
			     : "+r" (cmp)                      // %0
			     : "r" (target),                   // %1
			       "r" (new)                       // %2
			     : "memory");

	/* if the old value is still the same unchanged, we won, otherwise we
	 * store the refreshed old value.
	 */
	ret = cmp.r[0] == bck.r[0] && cmp.r[1] == bck.r[1];
	if (unlikely(!ret)) {
		/* update the old value on failure. Note that in this case the
		 * caller will likely relax and jump backwards so we don't care
		 * about this cost provided that it doesn't enlarge the fast
		 * code path.
		 */
		*(struct pair *)compare = cmp;
	}
	return ret;
}

#elif defined(__SIZEOF_INT128__) && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16) // no ARMv8.1-A atomics but 128-bit atomics

/* According to https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
 * we can use atomics on __int128. The availability of CAS is defined there:
 *   https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
 * However these usually involve a function call which can be expensive for some
 * cases, but gcc 10.2 and above can reroute the function call to either LL/SC for
 * v8.0 or LSE for v8.1+, which allows to use a more scalable version on v8.1+ at
 * the extra cost of a function call.
 */

/* returns 0 on failure, non-zero on success */
static __inline int __ha_cas_dw(void *target, void *compare, const void *set)
{
	return __atomic_compare_exchange((__int128*)target, (__int128*)compare, (const __int128*)set,
	                                 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

#else // neither ARMv8.1-A atomics nor 128-bit atomics

/* returns 0 on failure, non-zero on success */
static __inline int __ha_cas_dw(void *target, void *compare, void *set)
{
	void *value[2];
	uint64_t tmp1, tmp2;

	__asm__ __volatile__("1:"
                             "ldxp %0, %1, [%4]\n"
                             "mov %2, %0\n"
                             "mov %3, %1\n"
                             "eor %0, %0, %5\n"
                             "eor %1, %1, %6\n"
                             "orr %1, %0, %1\n"
                             "mov %w0, #0\n"
                             "cbnz %1, 2f\n"
                             "stxp %w0, %7, %8, [%4]\n"
                             "cbnz %w0, 1b\n"
                             "mov %w0, #1\n"
                             "2:"
                             : "=&r" (tmp1), "=&r" (tmp2), "=&r" (value[0]), "=&r" (value[1])
                             : "r" (target), "r" (((void **)(compare))[0]), "r" (((void **)(compare))[1]), "r" (((void **)(set))[0]), "r" (((void **)(set))[1])
                             : "cc", "memory");

	memcpy(compare, &value, sizeof(value));
        return (tmp1);
}
#endif // ARMv8.1-A atomics

#else /* unknown / unhandled architecture, fall back to generic barriers */

#define __ha_barrier_atomic_load __sync_synchronize
#define __ha_barrier_atomic_store __sync_synchronize
#define __ha_barrier_atomic_full __sync_synchronize
#define __ha_barrier_load __sync_synchronize
#define __ha_barrier_store __sync_synchronize
#define __ha_barrier_full __sync_synchronize
/* Note: there is no generic DWCAS */

/* short-lived CPU relaxation */
#define __ha_cpu_relax() ({ asm volatile(""); 1; })

#endif /* end of arch-specific barrier/dwcas */

static inline void __ha_compiler_barrier(void)
{
	__asm __volatile("" ::: "memory");
}

#endif /* USE_THREAD */


/* fallbacks to remap all undefined _HA_ATOMIC_* on to their safe equivalent */
#ifndef _HA_ATOMIC_BTR
#define _HA_ATOMIC_BTR HA_ATOMIC_BTR
#endif /* !_HA_ATOMIC_BTR */

#ifndef _HA_ATOMIC_BTS
#define _HA_ATOMIC_BTS HA_ATOMIC_BTS
#endif /* !_HA_ATOMIC_BTS */

#ifndef _HA_ATOMIC_CAS
#define _HA_ATOMIC_CAS HA_ATOMIC_CAS
#endif /* !_HA_ATOMIC_CAS */

#ifndef _HA_ATOMIC_DWCAS
#define _HA_ATOMIC_DWCAS HA_ATOMIC_DWCAS
#endif /* !_HA_ATOMIC_CAS */

#ifndef _HA_ATOMIC_ADD
#define _HA_ATOMIC_ADD HA_ATOMIC_ADD
#endif /* !_HA_ATOMIC_ADD */

#ifndef _HA_ATOMIC_ADD_FETCH
#define _HA_ATOMIC_ADD_FETCH HA_ATOMIC_ADD_FETCH
#endif /* !_HA_ATOMIC_ADD_FETCH */

#ifndef _HA_ATOMIC_FETCH_ADD
#define _HA_ATOMIC_FETCH_ADD HA_ATOMIC_FETCH_ADD
#endif /* !_HA_ATOMIC_FETCH_ADD */

#ifndef _HA_ATOMIC_SUB
#define _HA_ATOMIC_SUB HA_ATOMIC_SUB
#endif /* !_HA_ATOMIC_SUB */

#ifndef _HA_ATOMIC_SUB_FETCH
#define _HA_ATOMIC_SUB_FETCH HA_ATOMIC_SUB_FETCH
#endif /* !_HA_ATOMIC_SUB_FETCH */

#ifndef _HA_ATOMIC_FETCH_SUB
#define _HA_ATOMIC_FETCH_SUB HA_ATOMIC_FETCH_SUB
#endif /* !_HA_ATOMIC_FETCH_SUB */

#ifndef _HA_ATOMIC_INC
#define _HA_ATOMIC_INC HA_ATOMIC_INC
#endif /* !_HA_ATOMIC_INC */

#ifndef _HA_ATOMIC_DEC
#define _HA_ATOMIC_DEC HA_ATOMIC_DEC
#endif /* !_HA_ATOMIC_DEC */

#ifndef _HA_ATOMIC_AND
#define _HA_ATOMIC_AND HA_ATOMIC_AND
#endif /* !_HA_ATOMIC_AND */

#ifndef _HA_ATOMIC_AND_FETCH
#define _HA_ATOMIC_AND_FETCH HA_ATOMIC_AND_FETCH
#endif /* !_HA_ATOMIC_AND_FETCH */

#ifndef _HA_ATOMIC_FETCH_AND
#define _HA_ATOMIC_FETCH_AND HA_ATOMIC_FETCH_AND
#endif /* !_HA_ATOMIC_FETCH_AND */

#ifndef _HA_ATOMIC_OR
#define _HA_ATOMIC_OR HA_ATOMIC_OR
#endif /* !_HA_ATOMIC_OR */

#ifndef _HA_ATOMIC_OR_FETCH
#define _HA_ATOMIC_OR_FETCH HA_ATOMIC_OR_FETCH
#endif /* !_HA_ATOMIC_OR_FETCH */

#ifndef _HA_ATOMIC_FETCH_OR
#define _HA_ATOMIC_FETCH_OR HA_ATOMIC_FETCH_OR
#endif /* !_HA_ATOMIC_FETCH_OR */

#ifndef _HA_ATOMIC_XCHG
#define _HA_ATOMIC_XCHG HA_ATOMIC_XCHG
#endif /* !_HA_ATOMIC_XCHG */

#ifndef _HA_ATOMIC_STORE
#define _HA_ATOMIC_STORE HA_ATOMIC_STORE
#endif /* !_HA_ATOMIC_STORE */

#ifndef _HA_ATOMIC_LOAD
#define _HA_ATOMIC_LOAD HA_ATOMIC_LOAD
#endif /* !_HA_ATOMIC_LOAD */

#endif /* _HAPROXY_ATOMIC_H */
