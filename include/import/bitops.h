/*
 * bitops.h : macros and functions for bit operations.
 * (C) 2002 - Willy Tarreau - willy@ant-computing.com
 *
 */

#ifndef __BITOPS_H__
#define __BITOPS_H__

/* how many bits are needed to code the size of an int (eg: 32bits -> 5) */
#define	LONGSHIFT	5
#define LLONGSHIFT	6
#define LONGBITS	32
#define LLONGBITS	64

/* very fast FFS function : returns the position of the lowest 1 */
#define __ffs_fast32(___a) ({ \
    register int ___x, ___bits = 32; \
    if (___a) { \
        ___x = (___a); \
        ___bits--; \
	if (___x & 0x0000ffff) { ___x &= 0x0000ffff; ___bits -= 16;} \
	if (___x & 0x00ff00ff) { ___x &= 0x00ff00ff; ___bits -=  8;} \
	if (___x & 0x0f0f0f0f) { ___x &= 0x0f0f0f0f; ___bits -=  4;} \
	if (___x & 0x33333333) { ___x &= 0x33333333; ___bits -=  2;} \
	if (___x & 0x55555555) { ___x &= 0x55555555; ___bits -=  1;} \
    }\
    ___bits; \
    })

/* very fast FLS function : returns the position of the highest 1  */
#define __fls_fast32(___a) ({ \
    register int ___x, ___bits = 0; \
    if (___a) { \
        ___x = (___a); \
	if (___x & 0xffff0000) { ___x &= 0xffff0000; ___bits += 16;} \
	if (___x & 0xff00ff00) { ___x &= 0xff00ff00; ___bits +=  8;} \
	if (___x & 0xf0f0f0f0) { ___x &= 0xf0f0f0f0; ___bits +=  4;} \
	if (___x & 0xcccccccc) { ___x &= 0xcccccccc; ___bits +=  2;} \
	if (___x & 0xaaaaaaaa) { ___x &= 0xaaaaaaaa; ___bits +=  1;} \
    } else { \
	___bits = 32; \
    } \
    ___bits; \
    })

/* very fast FFS function working on 64 bits */
#define __ffs_fast64(___a) ({ \
    register int ___bits = 64; \
    register unsigned long  ___x = ((___a) >> 32); \
    if ((___a) & 0xffffffffUL) { \
        ___x = (___a) & 0xffffffffUL; \
	___bits -= 32; \
    } \
    if (___x) { \
        ___bits--; \
	if (___x & 0x0000ffff) { ___x &= 0x0000ffff; ___bits -= 16;} \
	if (___x & 0x00ff00ff) { ___x &= 0x00ff00ff; ___bits -=  8;} \
	if (___x & 0x0f0f0f0f) { ___x &= 0x0f0f0f0f; ___bits -=  4;} \
	if (___x & 0x33333333) { ___x &= 0x33333333; ___bits -=  2;} \
	if (___x & 0x55555555) { ___x &= 0x55555555; ___bits -=  1;} \
    }\
    ___bits; \
    })


/* very fast FLS function working on 64 bits */
#define __fls_fast64(___a) ({ \
    register int ___bits = 0; \
    register unsigned long ___x = (___a); \
    if (((unsigned long long)(___a)) >> 32) { \
        ___x = ((unsigned long long)(___a)) >> 32; \
	___bits += 32; \
    } \
    if (___x) { \
	if (___x & 0xffff0000) { ___x &= 0xffff0000; ___bits += 16;} \
	if (___x & 0xff00ff00) { ___x &= 0xff00ff00; ___bits +=  8;} \
	if (___x & 0xf0f0f0f0) { ___x &= 0xf0f0f0f0; ___bits +=  4;} \
	if (___x & 0xcccccccc) { ___x &= 0xcccccccc; ___bits +=  2;} \
	if (___x & 0xaaaaaaaa) { ___x &= 0xaaaaaaaa; ___bits +=  1;} \
    } else { \
	 ___bits += 32; \
    } \
    ___bits; \
    })

static int ffs_fast32(register unsigned long a) {
    return __ffs_fast32(a);
}

static int fls_fast32(unsigned long a) {
    return __fls_fast32(a);
}

static int ffs_fast64(unsigned long long a) {
    return __ffs_fast64(a);
}

static int fls_fast64(unsigned long long a) {
    return __fls_fast64(a);
}

#endif /* __BITOPS_H__ */
