/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _INTOPS_T_H_
#define _INTOPS_T_H_

/* size used for max length of decimal representation of long long int. */
#define NB_LLMAX_STR (sizeof("-9223372036854775807")-1)

/* number of itoa_str entries */
#define NB_ITOA_STR	16

/* returns 1 only if only zero or one bit is set in X, which means that X is a
 * power of 2, and 0 otherwise */
#define POWEROF2(x) (((x) & ((x)-1)) == 0)

/* return an integer of type <ret> with only the highest bit set. <ret> may be
 * both a variable or a type.
 */
#define MID_RANGE(ret) ((typeof(ret))1 << (8*sizeof(ret) - 1))

/* return the largest possible integer of type <ret>, with all bits set */
#define MAX_RANGE(ret) (~(typeof(ret))0)


#endif /* _INTOPS_T_H_ */
