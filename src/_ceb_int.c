/*
 * Compact Elastic Binary Trees - exported functions operating on integer keys
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

/* NOTE: this file is only meant to be included from other C files. It will
 * use the following private macros that must be defined by the caller:
 *   - CEB_KEY_TYPE:   uint32_t, uint64_t, unsigned long
 *   - CEB_KEY_MEMBER: member of the struct ceb_node holding the key
 *   - CEB_MKEY_PFX:   function name prefix for multi-key
 *   - CEB_UKEY_PFX:   function name prefix for unique keys
 *
 * The dump functions will only be build if CEB_ENABLE_DUMP is defined.
 */
#include "cebtree-prv.h"

/*
 *  Below are the functions that support duplicate keys (_ceb_*)
 */

/*****************************************************************************\
 * The declarations below always cause two functions to be declared, one     *
 * starting with "cebs_*" and one with "cebs_ofs_*" which takes a key offset *
 * just after the root. The one without kofs just has this argument omitted  *
 * from its declaration and replaced with sizeof(struct ceb_node) in the     *
 * call to the underlying functions.                                         *
\*****************************************************************************/

/* Inserts node <node> into tree <tree> based on its key that immediately
 * follows the node. Returns the inserted node or the one that already contains
 * the same key.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _insert, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_insert(root, node, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_insert(root, node, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* return the first node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, CEB_MKEY_PFX, _first, struct ceb_root *const *, root, ptrdiff_t, kofs)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_first(root, kofs, CEB_KT_U32, 0, &is_dup);
	else
		return _ceb_first(root, kofs, CEB_KT_U64, 0, &is_dup);
}

/* return the last node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, CEB_MKEY_PFX, _last, struct ceb_root *const *, root, ptrdiff_t, kofs)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_last(root, kofs, CEB_KT_U32, 0, &is_dup);
	else
		return _ceb_last(root, kofs, CEB_KT_U64, 0, &is_dup);
}

/* look up the specified key, and returns either the node containing it, or
 * NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _lookup, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_lookup(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* look up the specified key or the highest below it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _lookup_le, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_le(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_lookup_le(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* look up highest key below the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _lookup_lt, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_lt(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_lookup_lt(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* look up the specified key or the smallest above it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _lookup_ge, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_ge(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_lookup_ge(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* look up the smallest key above the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _lookup_gt, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_gt(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_lookup_gt(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _next_unique, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_next_unique(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_next_unique(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _prev_unique, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_prev_unique(root, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_prev_unique(root, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* search for the next node after the specified one containing the same value,
 * and return it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _next_dup, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_next_dup(root, kofs, CEB_KT_U32, key, 0, NULL, node);
	else
		return _ceb_next_dup(root, kofs, CEB_KT_U64, 0, key, NULL, node);
}

/* search for the prev node before the specified one containing the same value,
 * and return it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _prev_dup, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_prev_dup(root, kofs, CEB_KT_U32, key, 0, NULL, node);
	else
		return _ceb_prev_dup(root, kofs, CEB_KT_U64, 0, key, NULL, node);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _next, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_next(root, kofs, CEB_KT_U32, key, 0, NULL, node, &is_dup);
	else
		return _ceb_next(root, kofs, CEB_KT_U64, 0, key, NULL, node, &is_dup);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _prev, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_prev(root, kofs, CEB_KT_U32, key, 0, NULL, node, &is_dup);
	else
		return _ceb_prev(root, kofs, CEB_KT_U64, 0, key, NULL, node, &is_dup);
}

/* look up the specified node with its key and deletes it if found, and in any
 * case, returns the node.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _delete, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_delete(root, node, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_delete(root, node, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/* look up the specified key, and detaches it and returns it if found, or NULL
 * if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _pick, struct ceb_root **, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	int is_dup;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_delete(root, NULL, kofs, CEB_KT_U32, key, 0, NULL, &is_dup);
	else
		return _ceb_delete(root, NULL, kofs, CEB_KT_U64, 0, key, NULL, &is_dup);
}

/*
 *  Below are the functions that only support unique keys (_cebu_*)
 */

/*****************************************************************************\
 * The declarations below always cause two functions to be declared, one     *
 * starting with "cebu32_*" and one with "cebu32_ofs_*" which takes a key    *
 * offset just after the root. The one without kofs just has this argument   *
 * omitted from its declaration and replaced with sizeof(struct ceb_node) in *
 * the call to the underlying functions.                                     *
\*****************************************************************************/

/* Inserts node <node> into unique tree <tree> based on its key that
 * immediately follows the node. Returns the inserted node or the one
 * that already contains the same key.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _insert, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_insert(root, node, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_insert(root, node, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* return the first node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, CEB_UKEY_PFX, _first, struct ceb_root *const *, root, ptrdiff_t, kofs)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_first(root, kofs, CEB_KT_U32, 0, NULL);
	else
		return _ceb_first(root, kofs, CEB_KT_U64, 0, NULL);
}

/* return the last node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, CEB_UKEY_PFX, _last, struct ceb_root *const *, root, ptrdiff_t, kofs)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_last(root, kofs, CEB_KT_U32, 0, NULL);
	else
		return _ceb_last(root, kofs, CEB_KT_U64, 0, NULL);
}

/* look up the specified key, and returns either the node containing it, or
 * NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _lookup, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_lookup(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up the specified key or the highest below it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _lookup_le, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_le(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_lookup_le(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up highest key below the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _lookup_lt, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_lt(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_lookup_lt(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up the specified key or the smallest above it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _lookup_ge, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_ge(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_lookup_ge(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up the smallest key above the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _lookup_gt, struct ceb_root *const *, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_lookup_gt(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_lookup_gt(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _next, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_next_unique(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_next_unique(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _prev, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_prev_unique(root, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_prev_unique(root, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up the specified node with its key and deletes it if found, and in any
 * case, returns the node.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _delete, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node)
{
	CEB_KEY_TYPE key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_delete(root, node, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_delete(root, node, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/* look up the specified key, and detaches it and returns it if found, or NULL
 * if not found.
 */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _pick, struct ceb_root **, root, ptrdiff_t, kofs, CEB_KEY_TYPE, key)
{
	if (sizeof(CEB_KEY_TYPE) <= 4)
		return _ceb_delete(root, NULL, kofs, CEB_KT_U32, key, 0, NULL, NULL);
	else
		return _ceb_delete(root, NULL, kofs, CEB_KT_U64, 0, key, NULL, NULL);
}

/*
 * Functions used to dump trees in Dot format. These are only enabled if
 * CEB_ENABLE_DUMP is defined.
 */

#if defined(CEB_ENABLE_DUMP)

#include <stdio.h>
#define TO_STR(x) _TO_STR(x)
#define _TO_STR(x) #x

/* dumps a ceb_node tree using the default functions above. If a node matches
 * <ctx>, this one will be highlighted in red. If the <sub> value is non-null,
 * only a subgraph will be printed. If it's null, and root is non-null, then
 * the tree is dumped at once, otherwise if root is NULL, then a prologue is
 * dumped when label is not NULL, or the epilogue when label is NULL. As a
 * summary:
 *    sub  root label
 *     0   NULL NULL   epilogue only (closing brace and LF)
 *     0   NULL text   prologue with <text> as label
 *     0   tree *      prologue+tree+epilogue at once
 *    N>0  tree *      only the tree, after a prologue and before an epilogue
 */
CEB_FDECL5(void, CEB_MKEY_PFX, _default_dump, struct ceb_root *const *, root, ptrdiff_t, kofs, const char *, label, const void *, ctx, int, sub)
{
	if (!sub && label) {
		printf("\ndigraph " TO_STR(CEB_MKEY_PFX) "_tree {\n"
		       "  fontname=\"fixed\";\n"
		       "  fontsize=8\n"
		       "  label=\"%s\"\n"
		       "", label);

		printf("  node [fontname=\"fixed\" fontsize=8 shape=\"box\" style=\"filled\" color=\"black\" fillcolor=\"white\"];\n"
		       "  edge [fontname=\"fixed\" fontsize=8 style=\"solid\" color=\"magenta\" dir=\"forward\"];\n");
	} else
		printf("\n### sub %d ###\n\n", sub);

	if (root)
		ceb_imm_default_dump_tree(kofs, sizeof(CEB_KEY_TYPE) <= 4 ? CEB_KT_U32 : CEB_KT_U64, root, 0, NULL, 0, ctx, sub, NULL, NULL, NULL, NULL);

	if (!sub && (root || !label))
		printf("}\n");
}

#endif /* CEB_ENABLE_DUMP */
