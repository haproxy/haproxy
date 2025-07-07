/*
 * Compact Elastic Binary Trees - internal functions and types
 *
 * Copyright (C) 2014-2025 Willy Tarreau - w@1wt.eu
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

/* This file MUST NOT be included by public code, it contains macros, enums
 * with short names and function definitions that may clash with user code.
 * It may only be included by the respective types' C files.
 */

/*
 * These trees are optimized for adding the minimalest overhead to the stored
 * data. This version uses the node's pointer as the key, for the purpose of
 * quickly finding its neighbours.
 *
 * A few properties :
 * - the xor between two branches of a node cannot be zero unless the two
 *   branches are duplicate keys
 * - the xor between two nodes has *at least* the split bit set, possibly more
 * - the split bit is always strictly smaller for a node than for its parent,
 *   which implies that the xor between the keys of the lowest level node is
 *   always smaller than the xor between a higher level node. Hence the xor
 *   between the branches of a regular leaf is always strictly larger than the
 *   xor of its parent node's branches if this node is different, since the
 *   leaf is associated with a higher level node which has at least one higher
 *   level branch. The first leaf doesn't validate this but is handled by the
 *   rules below.
 * - during the descent, the node corresponding to a leaf is always visited
 *   before the leaf, unless it's the first inserted, nodeless leaf.
 * - the first key is the only one without any node, and it has both its
 *   branches pointing to itself during insertion to detect it (i.e. xor==0).
 * - a leaf is always present as a node on the path from the root, except for
 *   the inserted first key which has no node, and is recognizable by its two
 *   branches pointing to itself.
 * - a consequence of the rules above is that a non-first leaf appearing below
 *   a node will necessarily have an associated node with a split bit equal to
 *   or greater than the node's split bit.
 * - another consequence is that below a node, the split bits are different for
 *   each branches since both of them are already present above the node, thus
 *   at different levels, so their respective XOR values will be different.
 * - since all nodes in a given path have a different split bit, if a leaf has
 *   the same split bit as its parent node, it is necessary its associated leaf
 *
 * When descending along the tree, it is possible to know that a search key is
 * not present, because its XOR with both of the branches is stricly higher
 * than the inter-branch XOR. The reason is simple : the inter-branch XOR will
 * have its highest bit set indicating the split bit. Since it's the bit that
 * differs between the two branches, the key cannot have it both set and
 * cleared when comparing to the branch values. So xoring the key with both
 * branches will emit a higher bit only when the key's bit differs from both
 * branches' similar bit. Thus, the following equation :
 *      (XOR(key, L) > XOR(L, R)) && (XOR(key, R) > XOR(L, R))
 * is only true when the key should be placed above that node. Since the key
 * has a higher bit which differs from the node, either it has it set and the
 * node has it clear (same for both branches), or it has it clear and the node
 * has it set for both branches. For this reason it's enough to compare the key
 * with any node when the equation above is true, to know if it ought to be
 * present on the left or on the right side. This is useful for insertion and
 * for range lookups.
 */

#ifndef _CEBTREE_PRV_H
#define _CEBTREE_PRV_H

#include <sys/types.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include "cebtree.h"

/* A few utility functions and macros that we need below */

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

#if !defined(__GNUC__)
/* Some versions of glibc irresponsibly redefine __attribute__() to empty for
 * non-gcc compilers, and as such, silently break all constructors with other
 * other compilers. Let's make sure such incompatibilities are detected if any,
 * or that the attribute is properly enforced.
 */
#undef __attribute__
#define __attribute__(x) __attribute__(x)
#endif

/* Define the missing __builtin_prefetch() for tcc. */
#if defined(__TINYC__) && !defined(__builtin_prefetch)
#define __builtin_prefetch(addr, ...) do { } while (0)
#endif

/* __builtin_unreachable() was added in gcc 4.5 */
#if defined(__GNUC__) && (__GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
#define __has_builtin___builtin_unreachable 1  /* make __builtin_unreachable() return 1 */
#elif !__has_builtin(__builtin_unreachable)
#define __builtin_unreachable() do { } while (1)
#endif

/* FLSNZ: find last set bit for non-zero value. "Last" here means the highest
 * one. It returns a value from 1 to 32 for 1<<0 to 1<<31.
 */

#if defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)))
/* gcc >= 4.2 brings __builtin_clz() and __builtin_clzl(), also usable for
 * non-x86. However on x86 gcc does bad stuff if not properly handled. It xors
 * the bsr return with 31 and since it doesn't know how to deal with a xor
 * followed by a negation, it adds two instructions when using 32-clz(). Thus
 * instead we first cancel the xor using another one then add one. Even on ARM
 * that provides a clz instruction, it saves one register to proceed like this.
 */

#define flsnz8(x) flsnz32((unsigned char)x)

static inline __attribute__((always_inline)) unsigned int flsnz32(unsigned int x)
{
	return (__builtin_clz(x) ^ 31) + 1;
}

static inline __attribute__((always_inline)) unsigned int flsnz64(unsigned long long x)
{
	return (__builtin_clzll(x) ^ 63) + 1;
}

#elif (defined(__i386__) || defined(__x86_64__)) && !defined(__atom__) /* Not gcc >= 4.2 */
/* DO NOT USE ON ATOM! The instruction is emulated and is several times slower
 * than doing the math by hand.
 */
#define flsnz8(x) flsnz32((unsigned char)x)

static inline __attribute__((always_inline)) unsigned int flsnz32(unsigned int x)
{
	unsigned int r;
	__asm__("bsrl %1,%0\n"
	        : "=r" (r) : "rm" (x));
	return r + 1;
}

#if defined(__x86_64__)
static inline __attribute__((always_inline)) unsigned int flsnz64(unsigned long long x)
{
	unsigned long long r;
	__asm__("bsrq %1,%0\n"
	        : "=r" (r) : "rm" (x));
	return r + 1;
}
#else
static inline __attribute__((always_inline)) unsigned int flsnz64(unsigned long long x)
{
	unsigned int h;
	unsigned int bits = 32;

	h = x >> 32;
	if (!h) {
		h = x;
		bits = 0;
	}
	return flsnz32(h) + bits;
}
#endif

#else /* Neither gcc >= 4.2 nor x86, use generic code */

static inline __attribute__((always_inline)) unsigned int flsnz8(unsigned int x)
{
	unsigned int ret = 0;
	if (x >> 4) { x >>= 4; ret += 4; }
	return ret + ((0xFFFFAA50U >> (x << 1)) & 3) + 1;
}

#define flsnz32(___a) ({ \
	register unsigned int ___x, ___bits = 0; \
	___x = (___a); \
	if (___x & 0xffff0000) { ___x &= 0xffff0000; ___bits += 16;} \
	if (___x & 0xff00ff00) { ___x &= 0xff00ff00; ___bits +=  8;} \
	if (___x & 0xf0f0f0f0) { ___x &= 0xf0f0f0f0; ___bits +=  4;} \
	if (___x & 0xcccccccc) { ___x &= 0xcccccccc; ___bits +=  2;} \
	if (___x & 0xaaaaaaaa) { ___x &= 0xaaaaaaaa; ___bits +=  1;} \
	___bits + 1; \
	})

static inline __attribute__((always_inline)) unsigned int flsnz64(unsigned long long x)
{
	unsigned int h;
	unsigned int bits = 32;

	h = x >> 32;
	if (!h) {
		h = x;
		bits = 0;
	}
	return flsnz32(h) + bits;
}

#endif

#define flsnz_long(x) ((sizeof(long) > 4) ? flsnz64(x) : flsnz32(x))
#define flsnz(x) ((sizeof(x) > 4) ? flsnz64(x) : (sizeof(x) > 1) ? flsnz32(x) : flsnz8(x))

/* Compare blocks <a> and <b> byte-to-byte, from bit <ignore> to bit <len-1>.
 * Return the number of equal bits between strings, assuming that the first
 * <ignore> bits are already identical. It is possible to return slightly more
 * than <len> bits if <len> does not stop on a byte boundary and we find exact
 * bytes. Note that parts or all of <ignore> bits may be rechecked. It is only
 * passed here as a hint to speed up the check.
 */
static
#if defined(__OPTIMIZE_SIZE__)
__attribute__((noinline))
#else
inline __attribute__((always_inline))
#endif
size_t equal_bits(const unsigned char *a,
                  const unsigned char *b,
                  size_t ignore, size_t len)
{
	for (ignore >>= 3, a += ignore, b += ignore, ignore <<= 3;
	     ignore < len; ) {
		unsigned char c;

		a++; b++;
		ignore += 8;
		c = b[-1] ^ a[-1];

		if (c) {
			/* OK now we know that old and new differ at byte <ptr> and that <c> holds
			 * the bit differences. We have to find what bit is differing and report
			 * it as the number of identical bits. Note that low bit numbers are
			 * assigned to high positions in the byte, as we compare them as strings.
			 */
			ignore -= flsnz_long(c);
			break;
		}
	}
	return ignore;
}

/* Compare strings <a> and <b> byte-to-byte, from bit <ignore> to the last 0.
 * Return the number of equal bits between strings, assuming that the first
 * <ignore> bits are already identical. Note that parts or all of <ignore> bits
 * may be rechecked. It is only passed here as a hint to speed up the check.
 * The caller is responsible for not passing an <ignore> value larger than any
 * of the two strings. However, referencing any bit from the trailing zero is
 * permitted. Equal strings are reported as a negative number of bits, which
 * indicates the end was reached.
 */
static
#if defined(__OPTIMIZE_SIZE__)
__attribute__((noinline))
#else
inline __attribute__((always_inline))
#endif
size_t string_equal_bits(const unsigned char *a,
                         const unsigned char *b,
                         size_t ignore)
{
	unsigned char c, d;
	size_t beg;

	beg = ignore >> 3;

	/* skip known and identical bits. We stop at the first different byte
	 * or at the first zero we encounter on either side.
	 */
	for (;; beg += 2) {
		c = a[beg + 0];
		d = b[beg + 0];
		c ^= d;
		if (__builtin_expect(c != 0, 0))
			goto brk1;
		if (!d)
			goto same;
		c = a[beg + 1];
		d = b[beg + 1];
		c ^= d;
		if (__builtin_expect(c != 0, 0))
			goto brk2;
		if (!d)
			goto same;
	}
brk2:
	beg++;
brk1:

	/* OK now we know that a and b differ at byte <beg>.
	 * We have to find what bit is differing and report it as the number of
	 * identical bits. Note that low bit numbers are assigned to high positions
	 * in the byte, as we compare them as strings.
	 */
	return (beg << 3) + ((flsnz(c) - 1) ^ 7);
same:
	return (size_t)-1;
}

/* pointer tagging / untagging, to turn ceb_root to ceb_node and conversely */

/* tag an untagged pointer (node -> root) */
static inline struct ceb_root *_ceb_dotag(const struct ceb_node *node, const uintptr_t tag)
{
	return (struct ceb_root *)((uintptr_t)node + tag);
}

/* untag a tagged pointer (root -> node) */
static inline struct ceb_node *_ceb_untag(const struct ceb_root *node, const uintptr_t tag)
{
	return (struct ceb_node *)((uintptr_t)node - tag);
}

/* clear a pointer's tag, regardless of its previous value */
static inline struct ceb_node *_ceb_clrtag(const struct ceb_root *node)
{
	return (struct ceb_node *)((uintptr_t)node & ~(uintptr_t)1);
}

/* report the pointer's tag */
static inline uintptr_t _ceb_gettag(const struct ceb_root *node)
{
	return (uintptr_t)node & (uintptr_t)1;
}

/* These macros are used by upper level files to create two variants of their
 * exported functions:
 *   - one which uses sizeof(struct ceb_node) as the key offset, for nodes with
 *     adjacent keys ; these ones are named <pfx><sfx>(root, ...). This is
 *     defined when CEB_USE_BASE is defined.
 *   - one with an explicit key offset passed by the caller right after the
 *     root. This is defined when CEB_USE_OFST is defined.
 * Both rely on a forced inline version with a body that immediately follows
 * the declaration, so that the declaration looks like a single decorated
 * function while 2 are built in practice. There are variants for the basic one
 * with 0, 1 and 2 extra arguments after the root. The root and the key offset
 * are always the first two arguments, and the key offset never appears in the
 * first variant, it's always replaced by sizeof(struct ceb_node) in the calls
 * to the inline version.
 */
#if defined(CEB_USE_BASE)
# define _CEB_DEF_BASE(x) x
#else
# define _CEB_DEF_BASE(x)
#endif

#if defined(CEB_USE_OFST)
# define _CEB_DEF_OFST(x) x
#else
# define _CEB_DEF_OFST(x)
#endif

#define CEB_FDECL2(type, pfx, sfx, type1, arg1, type2, arg2) \
	_CEB_FDECL2(type, pfx, sfx, type1, arg1, type2, arg2)

#define _CEB_FDECL2(type, pfx, sfx, type1, arg1, type2, arg2)		\
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2);			\
	_CEB_DEF_BASE(type pfx##_imm##sfx(type1 arg1) {			\
		return _##pfx##sfx(arg1, sizeof(struct ceb_node));	\
	})								\
	_CEB_DEF_OFST(type pfx##_ofs##sfx(type1 arg1, type2 arg2) {	\
		return _##pfx##sfx(arg1, arg2);				\
	})								\
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2)
	/* function body follows */

#define CEB_FDECL3(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3) \
	_CEB_FDECL3(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3)

#define _CEB_FDECL3(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3) \
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3);		\
	_CEB_DEF_BASE(type pfx##_imm##sfx(type1 arg1, type3 arg3) {		\
		return _##pfx##sfx(arg1, sizeof(struct ceb_node), arg3); \
	})								\
	_CEB_DEF_OFST(type pfx##_ofs##sfx(type1 arg1, type2 arg2, type3 arg3) {	\
		return _##pfx##sfx(arg1, arg2, arg3);			\
	})								\
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3)
	/* function body follows */

#define CEB_FDECL4(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
	_CEB_FDECL4(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4)

#define _CEB_FDECL4(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
	_CEB_DEF_BASE(type pfx##_imm##sfx(type1 arg1, type3 arg3, type4 arg4) {	\
		return _##pfx##sfx(arg1, sizeof(struct ceb_node), arg3, arg4); \
	})								\
	_CEB_DEF_OFST(type pfx##_ofs##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
		return _##pfx##sfx(arg1, arg2, arg3, arg4);		\
	})								\
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4)
	/* function body follows */

#define CEB_FDECL5(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
	_CEB_FDECL5(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)

#define _CEB_FDECL5(type, pfx, sfx, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
	_CEB_DEF_BASE(type pfx##_imm##sfx(type1 arg1, type3 arg3, type4 arg4, type5 arg5) {	\
		return _##pfx##sfx(arg1, sizeof(struct ceb_node), arg3, arg4, arg5); \
	})										\
	_CEB_DEF_OFST(type pfx##_ofs##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) { \
		return _##pfx##sfx(arg1, arg2, arg3, arg4, arg5);	\
	})								\
	static inline __attribute__((always_inline))			\
	type _##pfx##sfx(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)
	/* function body follows */

/* tree walk method: key, left, right */
enum ceb_walk_meth {
	CEB_WM_FST,     /* look up "first" (walk left only) */
	CEB_WM_NXT,     /* look up "next" (walk right once then left) */
	CEB_WM_PRV,     /* look up "prev" (walk left once then right) */
	CEB_WM_LST,     /* look up "last" (walk right only) */
	/* all methods from CEB_WM_KEQ and above do have a key */
	CEB_WM_KEQ,     /* look up the node equal to the key  */
	CEB_WM_KGE,     /* look up the node greater than or equal to the key */
	CEB_WM_KGT,     /* look up the node greater than the key */
	CEB_WM_KLE,     /* look up the node lower than or equal to the key */
	CEB_WM_KLT,     /* look up the node lower than the key */
	CEB_WM_KNX,     /* look up the node's key first, then find the next */
	CEB_WM_KPR,     /* look up the node's key first, then find the prev */
};

enum ceb_key_type {
	CEB_KT_ADDR,    /* the key is the node's address */
	CEB_KT_U32,     /* 32-bit unsigned word in key_u32 */
	CEB_KT_U64,     /* 64-bit unsigned word in key_u64 */
	CEB_KT_MB,      /* fixed size memory block in (key_u64,key_ptr), direct storage */
	CEB_KT_IM,      /* fixed size memory block in (key_u64,key_ptr), indirect storage */
	CEB_KT_ST,      /* NUL-terminated string in key_ptr, direct storage */
	CEB_KT_IS,      /* NUL-terminated string in key_ptr, indirect storage */
};

union ceb_key_storage {
	uint32_t u32;
	uint64_t u64;
	unsigned long ul;
	unsigned char mb[0];
	unsigned char str[0];
	unsigned char *ptr; /* for CEB_KT_IS */
};

/* returns the ceb_key_storage pointer for node <n> and offset <o> */
#define NODEK(n, o) ((union ceb_key_storage*)(((char *)(n)) + (o)))

/* Generic tree descent function. It must absolutely be inlined so that the
 * compiler can eliminate the tests related to the various return pointers,
 * which must either point to a local variable in the caller, or be NULL.
 * It must not be called with an empty tree, it's the caller business to
 * deal with this special case. It returns in ret_root the location of the
 * pointer to the leaf (i.e. where we have to insert ourselves). The integer
 * pointed to by ret_nside will contain the side the leaf should occupy at
 * its own node, with the sibling being *ret_root. Note that keys for fixed-
 * size arrays are passed in key_ptr with their length in key_u64. For keyless
 * nodes whose address serves as the key, the pointer needs to be passed in
 * key_ptr, and pxor64 will be used internally.
 * The support for duplicates is advertised by ret_is_dup not being null; it
 * will be filled on return with an indication whether the node belongs to a
 * duplicate list or not.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_descend(struct ceb_root **root,
                              enum ceb_walk_meth meth,
                              ptrdiff_t kofs,
                              enum ceb_key_type key_type,
                              uint32_t key_u32,
                              uint64_t key_u64,
                              const void *key_ptr,
                              int *ret_nside,
                              struct ceb_root ***ret_root,
                              struct ceb_node **ret_lparent,
                              int *ret_lpside,
                              struct ceb_node **ret_nparent,
                              int *ret_npside,
                              struct ceb_node **ret_gparent,
                              int *ret_gpside,
                              struct ceb_root **ret_back,
                              int *ret_is_dup)
{
#if defined(__GNUC__) && (__GNUC__ >= 12) && !defined(__OPTIMIZE__)
/* Avoid a bogus warning with gcc 12 and above: it warns about negative
 * memcmp() length in non-existing code paths at -O0, as reported here:
 *    https://gcc.gnu.org/bugzilla/show_bug.cgi?id=114622
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overread"
#endif
	struct ceb_node *node;
	union ceb_key_storage *k;
	struct ceb_node *gparent = NULL;
	struct ceb_node *bnode = NULL;
	struct ceb_node *lparent;
	uint32_t pxor32 __attribute__((unused)) = ~0U;   // previous xor between branches
	uint64_t pxor64 __attribute__((unused)) = ~0ULL; // previous xor between branches
	int gpside = 0;   // side on the grand parent
	long lpside = 0;  // side on the leaf's parent
	long brside = 0;  // branch side when descending
	size_t llen = 0;  // left vs key matching length
	size_t rlen = 0;  // right vs key matching length
	size_t plen = 0;  // previous common len between branches
	int is_leaf = 0;  // set if the current node is a leaf

	/* the parent will be the (possibly virtual) node so that
	 * &lparent->l == root, i.e. container_of(root, struct ceb_node, b[0]).
	 */
	lparent = (struct ceb_node *)((char *)root - (long)&((struct ceb_node *)0)->b[0]);
	gparent = lparent;
	if (ret_nparent)
		*ret_nparent = NULL;
	if (ret_npside)
		*ret_npside = 0;

	/* for key-less descents we need to set the initial branch to take */
	switch (meth) {
	case CEB_WM_NXT:
	case CEB_WM_LST:
		brside = 1; // start right for next/last
		break;
	case CEB_WM_FST:
	case CEB_WM_PRV:
	default:
		brside = 0; // start left for first/prev
		break;
	}

	/* In case of deletion, we need the node's parent and side. It's
	 * normally discovered during the descent while comparing branches,
	 * but there's a case where it's not possible, it's when the root
	 * is the node's parent because the first node is the one we're
	 * looking for. So we have to perform this check here.
	 */
	if (meth >= CEB_WM_KEQ && ret_nparent && ret_npside) {
		union ceb_key_storage *k = NODEK(_ceb_clrtag(*root), kofs);

		if (((key_type == CEB_KT_MB || key_type == CEB_KT_IM) &&
		     (memcmp(key_ptr, ((key_type == CEB_KT_MB) ? k->mb : k->ptr), key_u64) == 0)) ||
		    ((key_type == CEB_KT_ST || key_type == CEB_KT_IS) &&
		     (strcmp(key_ptr, (const void *)((key_type == CEB_KT_ST) ? k->str : k->ptr)) == 0))) {
			*ret_nparent = lparent;
			*ret_npside  = lpside;
		}
	}

	/* the previous xor is initialized to the largest possible inter-branch
	 * value so that it can never match on the first test as we want to use
	 * it to detect a leaf vs node. That's achieved with plen==0 for arrays
	 * and pxorXX==~0 for scalars.
	 */
	node = _ceb_clrtag(*root);
	is_leaf = _ceb_gettag(*root);

	if (ret_lpside) {
		/* this is a deletion, benefits from prefetching */
		__builtin_prefetch(node->b[0], 0);
		__builtin_prefetch(node->b[1], 0);
	}

	while (1) {
		union ceb_key_storage *lks, *rks;
		struct ceb_node *ln, *rn, *next;
		struct ceb_root *lr, *rr;
		int next_leaf, lnl, rnl;

		lr = node->b[0]; // tagged versions
		rr = node->b[1];

		/* get a copy of the corresponding nodes */
		lnl = _ceb_gettag(lr);
		ln = _ceb_clrtag(lr);
		rnl = _ceb_gettag(rr);
		rn = _ceb_clrtag(rr);

		/* neither pointer is tagged */
		k = NODEK(node, kofs);

		if (is_leaf)
			break;

		/* Tests show that this is the most optimal location to start
		 * a prefetch for adjacent nodes.
		 */
		__builtin_prefetch(ln, 0);
		__builtin_prefetch(rn, 0);

		lks = NODEK(ln, kofs);
		rks = NODEK(rn, kofs);

		/* In the following block, we're dealing with type-specific
		 * operations which follow the same construct for each type:
		 *   1) calculate the new side for key lookups (otherwise keep
		 *      the current side, e.g. for first/last). Doing it early
		 *      allows the CPU to more easily predict next branches and
		 *      is faster by ~10%. For complex bits we keep the length
		 *      of identical bits instead of xor. We can also xor lkey
		 *      and rkey with key and use it everywhere later but it
		 *      doesn't seem to bring anything.
		 *
		 *   2) calculate the xor between the two sides to figure the
		 *      split bit position. If the new split bit is before the
		 *      previous one, we've reached a leaf: each leaf we visit
		 *      had its node part already visited. The only way to
		 *      distinguish them is that the inter-branch xor of the
		 *      leaf will be the node's one, and will necessarily be
		 *      larger than the previous node's xor if the node is
		 *      above (we've already checked for direct descendent
		 *      below). Said differently, if an inter-branch xor is
		 *      strictly larger than the previous one, it necessarily
		 *      is the one of an upper node, so what we're seeing
		 *      cannot be the node, hence it's the leaf. The case where
		 *      they're equal was already dealt with by the test at the
		 *      end of the loop (node points to self). For scalar keys,
		 *      we directly store the last xor value in pxorXX. For
		 *      arrays and strings, instead we store the previous equal
		 *      length.
		 *
		 *   3) for lookups, check if the looked key still has a chance
		 *      to be below: if it has a xor with both branches that is
		 *      larger than the xor between them, it cannot be there,
		 *      since it means that it differs from these branches by
		 *      at least one bit that's higher than the split bit,
		 *      hence not common to these branches. In such cases:
		 *      - if we're just doing a lookup, the key is not found
		 *        and we fail.
		 *      - if we are inserting, we must stop here and we have
		 *        the guarantee to be above a node.
		 *      - if we're deleting, it could be the key we were
		 *        looking for so we have to check for it as long as
		 *        it's still possible to keep a copy of the node's
		 *        parent.
		 */

		if (key_type == CEB_KT_U32) {
			uint32_t xor32;   // left vs right branch xor
			uint32_t kl, kr;

			kl = lks->u32; kr = rks->u32;
			if (meth >= CEB_WM_KEQ) {
				kl ^= key_u32; kr ^= key_u32;
				brside = kl >= kr;
			}

			xor32 = kl ^ kr;
			if (meth >= CEB_WM_KEQ) {
				/* let's stop if our key is not there */
				if (kl > xor32 && kr > xor32)
					break;

				if (ret_nparent && !*ret_nparent && ret_npside) {
					if (key_u32 == k->u32) {
						*ret_nparent = lparent;
						*ret_npside  = lpside;
					}
				}

				/* for pure lookups, no need to go down the leaf
				 * if we've found the key.
				 */
				if (!ret_root && !ret_lpside && !ret_lparent &&
				    !ret_gpside && !ret_gparent && !ret_back) {
					if (key_u32 == k->u32)
						break;
				}
			}
			pxor32 = xor32;
		}
		else if (key_type == CEB_KT_U64) {
			uint64_t xor64;   // left vs right branch xor
			uint64_t kl, kr;

			kl = lks->u64; kr = rks->u64;
			if (meth >= CEB_WM_KEQ) {
				kl ^= key_u64; kr ^= key_u64;
				brside = kl >= kr;
			}

			xor64 = kl ^ kr;
			if (meth >= CEB_WM_KEQ) {
				/* let's stop if our key is not there */
				if (kl > xor64 && kr > xor64)
					break;

				if (ret_nparent && !*ret_nparent && ret_npside) {
					if (key_u64 == k->u64) {
						*ret_nparent = lparent;
						*ret_npside  = lpside;
					}
				}

				/* for pure lookups, no need to go down the leaf
				 * if we've found the key.
				 */
				if (!ret_root && !ret_lpside && !ret_lparent &&
				    !ret_gpside && !ret_gparent && !ret_back) {
					if (key_u64 == k->u64)
						break;
				}
			}
			pxor64 = xor64;
		}
		else if (key_type == CEB_KT_ADDR) {
			uintptr_t xoraddr;   // left vs right branch xor
			uintptr_t kl, kr;

			kl = (uintptr_t)lks; kr = (uintptr_t)rks;
			if (meth >= CEB_WM_KEQ) {
				kl ^= (uintptr_t)key_ptr; kr ^= (uintptr_t)key_ptr;
				brside = kl >= kr;
			}

			xoraddr = kl ^ kr;
			if (meth >= CEB_WM_KEQ) {
				/* let's stop if our key is not there */
				if (kl > xoraddr && kr > xoraddr)
					break;

				if (ret_nparent && !*ret_nparent && ret_npside) {
					if ((uintptr_t)key_ptr == (uintptr_t)node) {
						*ret_nparent = lparent;
						*ret_npside  = lpside;
					}
				}

				/* for pure lookups, no need to go down the leaf
				 * if we've found the key.
				 */
				if (!ret_root && !ret_lpside && !ret_lparent &&
				    !ret_gpside && !ret_gparent && !ret_back) {
					if ((uintptr_t)key_ptr == (uintptr_t)node)
						break;
				}
			}
			pxor64 = xoraddr;
		}
		else if (key_type == CEB_KT_MB || key_type == CEB_KT_IM) {
			size_t xlen = 0; // left vs right matching length

			if (meth >= CEB_WM_KEQ) {
				/* measure identical lengths */
				llen = equal_bits(key_ptr, (key_type == CEB_KT_MB) ? lks->mb : lks->ptr, plen, key_u64 << 3);
				rlen = equal_bits(key_ptr, (key_type == CEB_KT_MB) ? rks->mb : rks->ptr, plen, key_u64 << 3);
				brside = llen <= rlen;
			}

			xlen = equal_bits((key_type == CEB_KT_MB) ? lks->mb : lks->ptr,
					  (key_type == CEB_KT_MB) ? rks->mb : rks->ptr, plen, key_u64 << 3);

			if (meth >= CEB_WM_KEQ) {
				/* let's stop if our key is not there */
				if (llen < xlen && rlen < xlen)
					break;

				if (ret_nparent && ret_npside && !*ret_nparent &&
				    ((llen == key_u64 << 3) || (rlen == key_u64 << 3))) {
					*ret_nparent = node;
					*ret_npside  = brside;
				}

				/* for pure lookups, no need to go down the leaf
				 * if we've found the key.
				 */
				if (!ret_root && !ret_lpside && !ret_lparent &&
				    !ret_gpside && !ret_gparent && !ret_back) {
					if (llen == key_u64 << 3) {
						node = ln;
						plen = llen;
						break;
					}
					if (rlen == key_u64 << 3) {
						node = rn;
						plen = rlen;
						break;
					}
				}
			}
			plen = xlen;
		}
		else if (key_type == CEB_KT_ST || key_type == CEB_KT_IS) {
			size_t xlen = 0; // left vs right matching length

			if (meth >= CEB_WM_KEQ) {
				/* Note that a negative length indicates an
				 * equal value with the final zero reached, but
				 * it is still needed to descend to find the
				 * leaf. We take that negative length for an
				 * infinite one, hence the uint cast.
				 */
				llen = string_equal_bits(key_ptr, (key_type == CEB_KT_ST) ? lks->str : lks->ptr, plen);
				rlen = string_equal_bits(key_ptr, (key_type == CEB_KT_ST) ? rks->str : rks->ptr, plen);
				brside = (size_t)llen <= (size_t)rlen;
				if (ret_nparent && ret_npside && !*ret_nparent &&
				    ((ssize_t)llen < 0 || (ssize_t)rlen < 0)) {
					*ret_nparent = node;
					*ret_npside  = brside;
				}

				/* for pure lookups, no need to go down the leaf
				 * if we've found the key.
				 */
				if (!ret_root && !ret_lpside && !ret_lparent &&
				    !ret_gpside && !ret_gparent && !ret_back) {
					if ((ssize_t)llen < 0) {
						node = ln;
						plen = llen;
						break;
					}
					if ((ssize_t)rlen < 0) {
						node = rn;
						plen = rlen;
						break;
					}
				}
			}

			/* the compiler cannot know this never happens and this helps it optimize the code */
			if ((ssize_t)plen < 0)
				__builtin_unreachable();

			xlen = string_equal_bits((key_type == CEB_KT_ST) ? lks->str : lks->ptr,
						 (key_type == CEB_KT_ST) ? rks->str : rks->ptr, plen);

			/* let's stop if our key is not there */
			if (meth >= CEB_WM_KEQ && llen < xlen && rlen < xlen)
				break;

			plen = xlen;
		}

		/* shift all copies by one */
		gparent = lparent;
		gpside = lpside;
		lparent = node;
		lpside = brside;
		if (brside) {
			if (meth == CEB_WM_KPR || meth == CEB_WM_KLE || meth == CEB_WM_KLT)
				bnode = node;
			next = rn;
			next_leaf = rnl;
			root = &node->b[1];

			/* change branch for key-less walks */
			if (meth == CEB_WM_NXT)
				brside = 0;
		}
		else {
			if (meth == CEB_WM_KNX || meth == CEB_WM_KGE || meth == CEB_WM_KGT)
				bnode = node;
			next = ln;
			next_leaf = lnl;
			root = &node->b[0];

			/* change branch for key-less walks */
			if (meth == CEB_WM_PRV)
				brside = 1;
		}

		if (next == node) {
			/* loops over itself, it's either a leaf or the single and last list element of a dup sub-tree */
			break;
		}

		/* let the compiler know there's no NULL in the tree */
		if (!next)
			__builtin_unreachable();

		node = next;
		is_leaf = next_leaf;
	}

	if (ret_is_dup) {
		if (is_leaf && _ceb_gettag(node->b[0]) && _ceb_gettag(node->b[1]) &&
		    (_ceb_clrtag(node->b[0]) != node || _ceb_clrtag(node->b[1]) != node)) {
			/* This leaf has two tagged pointers, with at least one not pointing
			 * to itself, it's not the nodeless leaf, it's a duplicate.
			 */
			*ret_is_dup = 1;
		} else {
			*ret_is_dup = 0;
		}
	}

	/* here we're on the closest node from the requested value. It may be
	 * slightly lower (has a zero where we expected a one) or slightly
	 * larger has a one where we expected a zero). Thus another check is
	 * still deserved, depending on the matching method.
	 */

	/* update the pointers needed for modifications (insert, delete) */
	if (ret_nside && meth >= CEB_WM_KEQ) {
		switch (key_type) {
		case CEB_KT_U32:
			*ret_nside = key_u32 >= k->u32;
			break;
		case CEB_KT_U64:
			*ret_nside = key_u64 >= k->u64;
			break;
		case CEB_KT_ADDR:
			*ret_nside = (uintptr_t)key_ptr >= (uintptr_t)node;
			break;
		case CEB_KT_MB:
		case CEB_KT_IM:
			*ret_nside = (uint64_t)plen / 8 == key_u64 ||
				memcmp(key_ptr + plen / 8, ((key_type == CEB_KT_MB) ? k->mb : k->ptr) + plen / 8, key_u64 - plen / 8) >= 0;
			break;

		case CEB_KT_ST:
		case CEB_KT_IS:
			*ret_nside = (ssize_t)plen < 0 ||
				strcmp(key_ptr + plen / 8, (const void *)((key_type == CEB_KT_ST) ? k->str : k->ptr) + plen / 8) >= 0;
			break;
		}
	}

	if (ret_root) {
		/* this node is going to be changed */
		*ret_root = root;
		__builtin_prefetch(root, 1);
	}

	/* info needed by delete */
	if (ret_lpside)
		*ret_lpside = lpside;

	if (ret_lparent) {
		/* this node is going to be changed */
		*ret_lparent = lparent;
		__builtin_prefetch(lparent, 1);
	}

	if (ret_gpside)
		*ret_gpside = gpside;

	if (ret_gparent)
		*ret_gparent = gparent;

	if (ret_back)
		*ret_back = _ceb_dotag(bnode, 0);

	if (meth >= CEB_WM_KEQ) {
		/* For lookups, an equal value means an instant return. For insertions,
		 * it is the same, we want to return the previously existing value so
		 * that the caller can decide what to do. For deletion, we also want to
		 * return the pointer that's about to be deleted.
		 */
		if (key_type == CEB_KT_U32) {
			if ((meth == CEB_WM_KEQ && k->u32 == key_u32) ||
			    (meth == CEB_WM_KNX && k->u32 == key_u32) ||
			    (meth == CEB_WM_KPR && k->u32 == key_u32) ||
			    (meth == CEB_WM_KGE && k->u32 >= key_u32) ||
			    (meth == CEB_WM_KGT && k->u32 >  key_u32) ||
			    (meth == CEB_WM_KLE && k->u32 <= key_u32) ||
			    (meth == CEB_WM_KLT && k->u32 <  key_u32))
				return node;
		}
		else if (key_type == CEB_KT_U64) {
			if ((meth == CEB_WM_KEQ && k->u64 == key_u64) ||
			    (meth == CEB_WM_KNX && k->u64 == key_u64) ||
			    (meth == CEB_WM_KPR && k->u64 == key_u64) ||
			    (meth == CEB_WM_KGE && k->u64 >= key_u64) ||
			    (meth == CEB_WM_KGT && k->u64 >  key_u64) ||
			    (meth == CEB_WM_KLE && k->u64 <= key_u64) ||
			    (meth == CEB_WM_KLT && k->u64 <  key_u64))
				return node;
		}
		else if (key_type == CEB_KT_ADDR) {
			if ((meth == CEB_WM_KEQ && (uintptr_t)node == (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KNX && (uintptr_t)node == (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KPR && (uintptr_t)node == (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KGE && (uintptr_t)node >= (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KGT && (uintptr_t)node >  (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KLE && (uintptr_t)node <= (uintptr_t)key_ptr) ||
			    (meth == CEB_WM_KLT && (uintptr_t)node <  (uintptr_t)key_ptr))
				return node;
		}
		else if (key_type == CEB_KT_MB || key_type == CEB_KT_IM) {
			int diff;

			if ((uint64_t)plen / 8 == key_u64)
				diff = 0;
			else
				diff = memcmp(((key_type == CEB_KT_MB) ? k->mb : k->ptr) + plen / 8, key_ptr + plen / 8, key_u64 - plen / 8);

			if ((meth == CEB_WM_KEQ && diff == 0) ||
			    (meth == CEB_WM_KNX && diff == 0) ||
			    (meth == CEB_WM_KPR && diff == 0) ||
			    (meth == CEB_WM_KGE && diff >= 0) ||
			    (meth == CEB_WM_KGT && diff >  0) ||
			    (meth == CEB_WM_KLE && diff <= 0) ||
			    (meth == CEB_WM_KLT && diff <  0))
				return node;
		}
		else if (key_type == CEB_KT_ST || key_type == CEB_KT_IS) {
			int diff;

			if ((ssize_t)plen < 0)
				diff = 0;
			else
				diff = strcmp((const void *)((key_type == CEB_KT_ST) ? k->str : k->ptr) + plen / 8, key_ptr + plen / 8);

			if ((meth == CEB_WM_KEQ && diff == 0) ||
			    (meth == CEB_WM_KNX && diff == 0) ||
			    (meth == CEB_WM_KPR && diff == 0) ||
			    (meth == CEB_WM_KGE && diff >= 0) ||
			    (meth == CEB_WM_KGT && diff >  0) ||
			    (meth == CEB_WM_KLE && diff <= 0) ||
			    (meth == CEB_WM_KLT && diff <  0))
				return node;
		}
	} else if (meth == CEB_WM_FST || meth == CEB_WM_LST) {
		return node;
	} else if (meth == CEB_WM_PRV || meth == CEB_WM_NXT) {
		return node;
	}

	/* lookups and deletes fail here */

	/* let's return NULL to indicate the key was not found. For a lookup or
	 * a delete, it's a failure. For an insert, it's an invitation to the
	 * caller to proceed since the element is not there.
	 */
	return NULL;
#if defined(__GNUC__) && (__GNUC__ >= 12) && !defined(__OPTIMIZE__)
#pragma GCC diagnostic pop
#endif
}

/*
 *  Below are the functions that support duplicate keys (_ceb_*)
 */

/* Generic tree insertion function for trees with duplicate keys. Inserts node
 * <node> into tree <tree>, with key type <key_type> and key <key_*>.
 * Returns the inserted node or the one that already contains the same key.
 * If <is_dup_ptr> is non-null, then duplicates are permitted and this variable
 * is used to temporarily carry an internal state.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_insert(struct ceb_root **root,
                             struct ceb_node *node,
                             ptrdiff_t kofs,
                             enum ceb_key_type key_type,
                             uint32_t key_u32,
                             uint64_t key_u64,
                             const void *key_ptr,
                             int *is_dup_ptr)
{
	struct ceb_root **parent;
	struct ceb_node *ret;
	int nside;

	if (!*root) {
		/* empty tree, insert a leaf only */
		node->b[0] = node->b[1] = _ceb_dotag(node, 1);
		*root = _ceb_dotag(node, 1);
		return node;
	}

	ret = _ceb_descend(root, CEB_WM_KEQ, kofs, key_type, key_u32, key_u64, key_ptr, &nside, &parent, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);

	if (!ret) {
		/* The key was not in the tree, we can insert it. Better use an
		 * "if" like this because the inline function above already has
		 * quite identifiable code paths. This reduces the code and
		 * optimizes it a bit.
		 */
		if (nside) {
			node->b[1] = _ceb_dotag(node, 1);
			node->b[0] = *parent;
		} else {
			node->b[0] = _ceb_dotag(node, 1);
			node->b[1] = *parent;
		}
		*parent = _ceb_dotag(node, 0);
		ret = node;
	} else if (is_dup_ptr) {
		/* The key was found. We must insert after it as the last
		 * element of the dups list, which means that our left branch
		 * will point to the key, the right one to the first dup
		 * (i.e. previous dup's right if it exists, otherwise ourself)
		 * and the parent must point to us.
		 */
		node->b[0] = *parent;

		if (*is_dup_ptr) {
			node->b[1] = _ceb_untag(*parent, 1)->b[1];
			_ceb_untag(*parent, 1)->b[1] = _ceb_dotag(node, 1);
		} else {
			node->b[1] = _ceb_dotag(node, 1);
		}
		*parent = _ceb_dotag(node, 1);
		ret = node;
	}
	return ret;
}

/* Returns the first node or NULL if not found, assuming a tree made of keys of
 * type <key_type>, and optionally <key_len> for fixed-size arrays (otherwise 0).
 * If the tree starts with duplicates, the first of them is returned.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_first(struct ceb_root *const *root,
                            ptrdiff_t kofs,
                            enum ceb_key_type key_type,
                            uint64_t key_len,
                            int *is_dup_ptr)
{
	struct ceb_node *node;

	if (!*root)
		return NULL;

	node = _ceb_descend((struct ceb_root **)root, CEB_WM_FST, kofs, key_type, 0, key_len, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
	if (node && is_dup_ptr && *is_dup_ptr) {
		/* on a duplicate, the first node is right->left and it's a leaf */
		node = _ceb_untag(_ceb_untag(node->b[1], 1)->b[0], 1);
	}
	return node;
}

/* Returns the last node or NULL if not found, assuming a tree made of keys of
 * type <key_type>, and optionally <key_len> for fixed-size arrays (otherwise 0).
 * If the tree ends with duplicates, the last of them is returned.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_last(struct ceb_root *const *root,
                           ptrdiff_t kofs,
                           enum ceb_key_type key_type,
                           uint64_t key_len,
                           int *is_dup_ptr)
{
	if (!*root)
		return NULL;

	/* note for duplicates: the current scheme always returns the last one by default */
	return _ceb_descend((struct ceb_root **)root, CEB_WM_LST, kofs, key_type, 0, key_len, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the next
 * node after the one containing the key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>. The
 * approach consists in looking up that node first, recalling the last time a
 * left turn was made, and returning the first node along the right branch at
 * that fork.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_next_unique(struct ceb_root *const *root,
                                  ptrdiff_t kofs,
                                  enum ceb_key_type key_type,
                                  uint32_t key_u32,
                                  uint64_t key_u64,
                                  const void *key_ptr,
                                  int *is_dup_ptr)
{
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	if (!_ceb_descend((struct ceb_root **)root, CEB_WM_KNX, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr))
		return NULL;

	if (!restart)
		return NULL;

	return _ceb_descend(&restart, CEB_WM_NXT, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the prev
 * node before the one containing the key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>. The
 * approach consists in looking up that node first, recalling the last time a
 * right turn was made, and returning the last node along the left branch at
 * that fork.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_prev_unique(struct ceb_root *const *root,
                                  ptrdiff_t kofs,
                                  enum ceb_key_type key_type,
                                  uint32_t key_u32,
                                  uint64_t key_u64,
                                  const void *key_ptr,
                                  int *is_dup_ptr)
{
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	if (!_ceb_descend((struct ceb_root **)root, CEB_WM_KPR, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr))
		return NULL;

	if (!restart)
		return NULL;

	return _ceb_descend(&restart, CEB_WM_PRV, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the next
 * node after <from> also containing key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_next_dup(struct ceb_root *const *root,
                               ptrdiff_t kofs,
                               enum ceb_key_type key_type,
                               uint32_t key_u32,
                               uint64_t key_u64,
                               const void *key_ptr,
                               const struct ceb_node *from)
{
	struct ceb_node *node;
	int is_dup;

	if (!*root)
		return NULL;

	node = _ceb_descend((struct ceb_root **)root, CEB_WM_KNX, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &is_dup);
	if (!node)
		return NULL;

	/* Normally at this point, if node != from, we've found a node that
	 * differs from the one we're starting from, which indicates that
	 * the starting point belongs to a dup list and is not the last one.
	 * We must then visit the other members. We cannot navigate from the
	 * regular leaf node (the first one) but we can easily verify if we're
	 * on that one by checking if it's node->b[1]->b[0], in which case we
	 * jump to node->b[1]. Otherwise we take from->b[1].
	 */
	if (node != from) {
		if (_ceb_untag(node->b[1], 1)->b[0] == _ceb_dotag(from, 1))
			return _ceb_untag(node->b[1], 1);
		else
			return _ceb_untag(from->b[1], 1);
	}

	/* there's no other dup here */
	return NULL;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the prev
 * node before <from> also containing key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_prev_dup(struct ceb_root *const *root,
                               ptrdiff_t kofs,
                               enum ceb_key_type key_type,
                               uint32_t key_u32,
                               uint64_t key_u64,
                               const void *key_ptr,
                               const struct ceb_node *from)
{
	struct ceb_node *node;
	int is_dup;

	if (!*root)
		return NULL;

	node = _ceb_descend((struct ceb_root **)root, CEB_WM_KPR, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &is_dup);
	if (!node)
		return NULL;

	/* Here we have several possibilities:
	 *   - from == node => we've found our node. It may be a unique node,
	 *     or the last one of a dup series. We'll sort that out thanks to
	 *     is_dup, and if it's a dup, we'll use node->b[0].
	 *   - from is not the first dup, so we haven't visited them all yet,
	 *     hence we visit node->b[0] to switch to the previous dup.
	 *   - from is the first dup so we've visited them all.
	 */
	if (is_dup && (node == from || _ceb_untag(node->b[1], 1)->b[0] != _ceb_dotag(from, 1)))
		return _ceb_untag(from->b[0], 1);

	/* there's no other dup here */
	return NULL;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the next
 * node after <from> which contains key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>. The
 * approach consists in looking up that node first, recalling the last time a
 * left turn was made, and returning the first node along the right branch at
 * that fork. In case the current node belongs to a duplicate list, all dups
 * will be visited in insertion order prior to jumping to different keys.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_next(struct ceb_root *const *root,
                           ptrdiff_t kofs,
                           enum ceb_key_type key_type,
                           uint32_t key_u32,
                           uint64_t key_u64,
                           const void *key_ptr,
                           const struct ceb_node *from,
                           int *is_dup_ptr)
{
	struct ceb_root *restart;
	struct ceb_node *node;

	if (!*root)
		return NULL;

	node = _ceb_descend((struct ceb_root **)root, CEB_WM_KNX, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (!node)
		return NULL;

	/* Normally at this point, if node != from, we've found a node that
	 * differs from the one we're starting from, which indicates that
	 * the starting point belongs to a dup list and is not the last one.
	 * We must then visit the other members. We cannot navigate from the
	 * regular leaf node (the first one) but we can easily verify if we're
	 * on that one by checking if it's _ceb_untag(node->b[1], 0)->b[0], in which case we
	 * jump to node->b[1]. Otherwise we take from->b[1].
	 */
	if (node != from) {
		if (_ceb_untag(node->b[1], 1)->b[0] == _ceb_dotag(from, 1))
			return _ceb_untag(node->b[1], 1);
		else
			return _ceb_untag(from->b[1], 1);
	}

	/* Here the looked up node was found (node == from) and we can look up
	 * the next unique one if any.
	 */
	if (!restart)
		return NULL;

	/* this look up will stop on the topmost dup in a sub-tree which is
	 * also the last one. Thanks to restart we know that this entry exists.
	 */
	node = _ceb_descend(&restart, CEB_WM_NXT, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
	if (node && is_dup_ptr && *is_dup_ptr) {
		/* on a duplicate, the first node is right->left and it's a leaf */
		node = _ceb_untag(_ceb_untag(node->b[1], 1)->b[0], 1);
	}
	return node;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the prev
 * node before the one containing the key <key_*>. Returns NULL if not found.
 * It's up to the caller to pass the current node's key in <key_*>. The
 * approach consists in looking up that node first, recalling the last time a
 * right turn was made, and returning the last node along the left branch at
 * that fork. In case the current node belongs to a duplicate list, all dups
 * will be visited in reverse insertion order prior to jumping to different
 * keys.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_prev(struct ceb_root *const *root,
                           ptrdiff_t kofs,
                           enum ceb_key_type key_type,
                           uint32_t key_u32,
                           uint64_t key_u64,
                           const void *key_ptr,
                           const struct ceb_node *from,
                           int *is_dup_ptr)
{
	struct ceb_root *restart;
	struct ceb_node *node;

	if (!*root)
		return NULL;

	node = _ceb_descend((struct ceb_root **)root, CEB_WM_KPR, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (!node)
		return NULL;

	/* Here we have several possibilities:
	 *   - from == node => we've found our node. It may be a unique node,
	 *     or the last one of a dup series. We'll sort that out thanks to
	 *     is_dup, and if it's a dup, we'll use node->b[0].
	 *   - from is not the first dup, so we haven't visited them all yet,
	 *     hence we visit node->b[0] to switch to the previous dup.
	 *   - from is the first dup so we've visited them all, we now need
	 *     to jump to the previous unique value.
	 */
	if (is_dup_ptr && *is_dup_ptr && (node == from || _ceb_untag(node->b[1], 1)->b[0] != _ceb_dotag(from, 1)))
		return _ceb_untag(from->b[0], 1);

	/* look up the previous unique entry */
	if (!restart)
		return NULL;

	/* Note that the descent stops on the last dup which is the one we want */
	return _ceb_descend(&restart, CEB_WM_PRV, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the first
 * node containing the key <key_*>. Returns NULL if not found.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_lookup(struct ceb_root *const *root,
                             ptrdiff_t kofs,
                             enum ceb_key_type key_type,
                             uint32_t key_u32,
                             uint64_t key_u64,
                             const void *key_ptr,
                             int *is_dup_ptr)
{
	struct ceb_node *ret;

	if (!*root)
		return NULL;

	ret = _ceb_descend((struct ceb_root **)root, CEB_WM_KEQ, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
	if (ret && is_dup_ptr && *is_dup_ptr) {
		/* on a duplicate, the first node is right->left and it's a leaf */
		ret = _ceb_untag(_ceb_untag(ret->b[1], 1)->b[0], 1);
	}
	return ret;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the last
 * node containing the key <key_*> or the highest one that's lower than it.
 * Returns NULL if not found.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_lookup_le(struct ceb_root *const *root,
                                ptrdiff_t kofs,
                                enum ceb_key_type key_type,
                                uint32_t key_u32,
                                uint64_t key_u64,
                                const void *key_ptr,
                                int *is_dup_ptr)
{
	struct ceb_node *ret = NULL;
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	/* note that for duplicates, we already find the last one */
	ret = _ceb_descend((struct ceb_root **)root, CEB_WM_KLE, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (ret)
		return ret;

	if (!restart)
		return NULL;

	return _ceb_descend(&restart, CEB_WM_PRV, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the last
 * node containing the greatest key that is strictly lower than <key_*>.
 * Returns NULL if not found. It's very similar to next() except that the
 * looked up value doesn't need to exist.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_lookup_lt(struct ceb_root *const *root,
                                ptrdiff_t kofs,
                                enum ceb_key_type key_type,
                                uint32_t key_u32,
                                uint64_t key_u64,
                                const void *key_ptr,
                                int *is_dup_ptr)
{
	struct ceb_node *ret = NULL;
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	/* note that for duplicates, we already find the last one */
	ret = _ceb_descend((struct ceb_root **)root, CEB_WM_KLT, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (ret)
		return ret;

	if (!restart)
		return NULL;

	return _ceb_descend(&restart, CEB_WM_PRV, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
}

/* Searches in the tree <root> made of keys of type <key_type>, for the first
 * node containing the key <key_*> or the smallest one that's greater than it.
 * Returns NULL if not found. If <is_dup_ptr> is non-null, then duplicates are
 * permitted and this variable is used to temporarily carry an internal state.

 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_lookup_ge(struct ceb_root *const *root,
                                ptrdiff_t kofs,
                                enum ceb_key_type key_type,
                                uint32_t key_u32,
                                uint64_t key_u64,
                                const void *key_ptr,
                                int *is_dup_ptr)
{
	struct ceb_node *ret = NULL;
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	ret = _ceb_descend((struct ceb_root **)root, CEB_WM_KGE, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (!ret) {
		if (!restart)
			return NULL;

		ret = _ceb_descend(&restart, CEB_WM_NXT, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
	}

	if (ret && is_dup_ptr && *is_dup_ptr) {
		/* on a duplicate, the first node is right->left and it's a leaf */
		ret = _ceb_untag(_ceb_untag(ret->b[1], 1)->b[0], 1);
	}
	return ret;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the first
 * node containing the lowest key that is strictly greater than <key_*>. Returns
 * NULL if not found. It's very similar to prev() except that the looked up
 * value doesn't need to exist. If <is_dup_ptr> is non-null, then duplicates are
 * permitted and this variable is used to temporarily carry an internal state.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_lookup_gt(struct ceb_root *const *root,
                                ptrdiff_t kofs,
                                enum ceb_key_type key_type,
                                uint32_t key_u32,
                                uint64_t key_u64,
                                const void *key_ptr,
                                int *is_dup_ptr)
{
	struct ceb_node *ret = NULL;
	struct ceb_root *restart;

	if (!*root)
		return NULL;

	ret = _ceb_descend((struct ceb_root **)root, CEB_WM_KGT, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &restart, is_dup_ptr);
	if (!ret) {
		if (!restart)
			return NULL;

		ret = _ceb_descend(&restart, CEB_WM_NXT, kofs, key_type, 0, key_u64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, is_dup_ptr);
	}

	if (ret && is_dup_ptr && *is_dup_ptr) {
		/* on a duplicate, the first node is right->left and it's a leaf */
		ret = _ceb_untag(_ceb_untag(ret->b[1], 1)->b[0], 1);
	}
	return ret;
}

/* Searches in the tree <root> made of keys of type <key_type>, for the node
 * that contains the key <key_*>, and deletes it. If <node> is non-NULL, a
 * check is performed and the node found is deleted only if it matches. The
 * found node is returned in any case, otherwise NULL if not found. A deleted
 * node is detected since it has b[0]==NULL, which this functions also clears
 * after operation. The function is idempotent, so it's safe to attempt to
 * delete an already deleted node (NULL is returned in this case since the node
 * was not in the tree). If <is_dup_ptr> is non-null, then duplicates are
 * permitted and this variable is used to temporarily carry an internal state.
 */
static inline __attribute__((always_inline))
struct ceb_node *_ceb_delete(struct ceb_root **root,
                             struct ceb_node *node,
                             ptrdiff_t kofs,
                             enum ceb_key_type key_type,
                             uint32_t key_u32,
                             uint64_t key_u64,
                             const void *key_ptr,
                             int *is_dup_ptr)
{
	struct ceb_node *lparent, *nparent, *gparent;
	int lpside, npside, gpside;
	struct ceb_node *ret = NULL;

	if (node && !node->b[0]) {
		/* NULL on a branch means the node is not in the tree */
		return NULL;
	}

	if (!*root) {
		/* empty tree, the node cannot be there */
		goto done;
	}

	ret = _ceb_descend(root, CEB_WM_KEQ, kofs, key_type, key_u32, key_u64, key_ptr, NULL, NULL,
			   &lparent, &lpside, &nparent, &npside, &gparent, &gpside, NULL, is_dup_ptr);

	if (!ret) {
		/* key not found */
		goto done;
	}

	if (is_dup_ptr && *is_dup_ptr) {
		/* the node to be deleted belongs to a dup sub-tree whose ret
		 * is the last. The possibilities here are:
		 *   1) node==NULL => unspecified, we delete the first one,
		 *      which is the tree leaf. The tree node (if it exists)
		 *      is replaced by the first dup. There's nothing else to
		 *      change.
		 *   2) node is the tree leaf. The tree node (if it exists)
		 *      is replaced by the first dup.
		 *   3) node is a dup. We just delete the dup.
		 *      In order to delete a dup, there are 4 cases:
		 *        a) node==last and there's a single dup, it's this one
		 *           -> *parent = node->b[0];
		 *        b) node==last and there's another dup:
		 *           -> *parent = node->b[0];
		 *              node->b[0]->b[1] = node->b[1];
		 *              (or (*parent)->b[1] = node->b[1] covers a and b)
		 *        c) node==first != last:
		 *           -> node->b[1]->b[0] = node->b[0];
		 *              last->b[1] = node->b[1];
		 *              (or (*parent)->b[1] = node->b[1] covers a,b,c)
		 *        d) node!=first && !=last:
		 *           -> node->b[1]->b[0] = node->b[0];
		 *              node->b[0]->b[1] = node->b[1];
		 *      a,b,c,d can be simplified as:
		 *         ((node == first) ? last : node->b[0])->b[1] = node->b[1];
		 *         *((node == last) ? parent : &node->b[1]->b[0]) = node->b[0];
		 */
		struct ceb_node *first, *last;

		last = ret;
		first = _ceb_untag(last->b[1], 1);

		/* cases 1 and 2 below */
		if (!node || node == _ceb_untag(first->b[0], 1)) {
			/* node unspecified or the first, remove the leaf and
			 * convert the first entry to it.
			 */
			ret = _ceb_untag(first->b[0], 1); // update return node
			last->b[1] = first->b[1]; // new first (remains OK if last==first)

			if (ret->b[0] != _ceb_dotag(ret, 1) || ret->b[1] != _ceb_dotag(ret, 1)) {
				/* not the nodeless leaf, a node exists, put it
				 * on the first and update its parent.
				 */
				first->b[0] = ret->b[0];
				first->b[1] = ret->b[1];
				nparent->b[npside] = _ceb_dotag(first, 0);
			}
			else {
				/* first becomes the nodeless leaf since we only keep its leaf */
				first->b[0] = first->b[1] = _ceb_dotag(first, 1);
			}
			/* first becomes a leaf, it must be tagged */
			if (last != first)
				_ceb_untag(last->b[1], 1)->b[0] = _ceb_dotag(first, 1);
			/* done */
		} else {
			/* case 3: the node to delete is a dup, we only have to
			 * manipulate the list.
			 */
			ret = node;
			((node == first) ? last : _ceb_untag(node->b[0], 1))->b[1] = node->b[1];
			*((node == last) ? &lparent->b[lpside] : &_ceb_untag(node->b[1], 1)->b[0]) = node->b[0];
			/* done */
		}
		goto mark_and_leave;
	}

	/* ok below the returned value is a real leaf, we have to adjust the tree */

	if (ret == node || !node) {
		if (&lparent->b[0] == root) {
			/* there was a single entry, this one, so we're just
			 * deleting the nodeless leaf.
			 */
			*root = NULL;
			goto mark_and_leave;
		}

		/* then we necessarily have a gparent */
		gparent->b[gpside] = lparent->b[!lpside];

		if (lparent == ret) {
			/* we're removing the leaf and node together, nothing
			 * more to do.
			 */
			goto mark_and_leave;
		}

		if (ret->b[0] == ret->b[1]) {
			/* we're removing the node-less item, the parent will
			 * take this role.
			 */
			lparent->b[0] = lparent->b[1] = _ceb_dotag(lparent, 1);
			goto mark_and_leave;
		}

		/* more complicated, the node was split from the leaf, we have
		 * to find a spare one to switch it. The parent node is not
		 * needed anymore so we can reuse it.
		 */
		lparent->b[0] = ret->b[0];
		lparent->b[1] = ret->b[1];
		nparent->b[npside] = _ceb_dotag(lparent, 0);

	mark_and_leave:
		/* now mark the node as deleted */
		ret->b[0] = NULL;
	}
done:
	return ret;
}

//#if defined(CEB_ENABLE_DUMP)
/* The dump functions are in cebtree-dbg.c */

void ceb_imm_default_dump_root(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root, const void *ctx, int sub);
void ceb_imm_default_dump_node(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub);
void ceb_imm_default_dump_dups(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub);
void ceb_imm_default_dump_leaf(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub);
const struct ceb_node *ceb_imm_default_dump_tree(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root,
                                             uint64_t pxor, const void *last, int level, const void *ctx, int sub,
                                             void (*root_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root, const void *ctx, int sub),
                                             void (*node_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub),
                                             void (*dups_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub),
                                             void (*leaf_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub));
//#endif /* CEB_ENABLE_DUMP */

#endif /* _CEBTREE_PRV_H */
