/*
 * Compact Elastic Binary Trees - exported functions operating on mb keys
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
 *   - CEB_KEY_TYPE:   CEB_KT_IM, CEB_KT_MB
 *   - CEB_KEY_MEMBER: member of the struct ceb_node holding the key
 *   - CEB_MKEY_PFX:   function name prefix for multi-key
 *   - CEB_UKEY_PFX:   function name prefix for unique keys
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
 * follows the node and for <len> bytes. Returns the inserted node or the one
 * that already contains the same key.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _insert, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_insert(root, node, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* return the first node or NULL if not found. */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _first, struct ceb_root *const *, root, ptrdiff_t, kofs, size_t, len)
{
	int is_dup;

	return _ceb_first(root, kofs, CEB_KEY_TYPE, len, &is_dup);
}

/* return the last node or NULL if not found. */
CEB_FDECL3(struct ceb_node *, CEB_MKEY_PFX, _last, struct ceb_root *const *, root, ptrdiff_t, kofs, size_t, len)
{
	int is_dup;

	return _ceb_last(root, kofs, CEB_KEY_TYPE, len, &is_dup);
}

/* look up the specified key <key> of length <len>, and returns either the node
 * containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _lookup, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_lookup(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* look up the specified key or the highest below it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _lookup_le, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_lookup_le(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* look up highest key below the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _lookup_lt, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_lookup_lt(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* look up the specified key or the smallest above it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _lookup_ge, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_lookup_ge(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* look up the smallest key above the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _lookup_gt, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_lookup_gt(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _next_unique, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_next_unique(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _prev_unique, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_prev_unique(root, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* search for the next node after the specified one containing the same value,
 * and return it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _next_dup, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_next_dup(root, kofs, CEB_KEY_TYPE, 0, len, key, node);
}

/* search for the prev node before the specified one containing the same value,
 * and return it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _prev_dup, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_prev_dup(root, kofs, CEB_KEY_TYPE, 0, len, key, node);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _next, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_next(root, kofs, CEB_KEY_TYPE, 0, len, key, node, &is_dup);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _prev, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_prev(root, kofs, CEB_KEY_TYPE, 0, len, key, node, &is_dup);
}

/* look up the specified node with its key and deletes it if found, and in any
 * case, returns the node. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _delete, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;
	int is_dup;

	return _ceb_delete(root, node, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/* look up the specified key, and detaches it and returns it if found, or NULL
 * if not found. The <len> field must correspond to the key length in bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_MKEY_PFX, _pick, struct ceb_root **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	int is_dup;

	return _ceb_delete(root, NULL, kofs, CEB_KEY_TYPE, 0, len, key, &is_dup);
}

/*
 *  Below are the functions that only support unique keys (_cebu_*)
 */

/*****************************************************************************\
 * The declarations below always cause two functions to be declared, one     *
 * starting with "cebub_*" and one with "cebub_ofs_*" which takes a key      *
 * offset just after the root. The one without kofs just has this argument   *
 * omitted from its declaration and replaced with sizeof(struct ceb_node) in *
 * the call to the underlying functions.                                     *
\*****************************************************************************/

/* Inserts node <node> into unique tree <tree> based on its key that
 * immediately follows the node and for <len> bytes. Returns the
 * inserted node or the one that already contains the same key.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _insert, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_insert(root, node, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* return the first node or NULL if not found. */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _first, struct ceb_root *const *, root, ptrdiff_t, kofs, size_t, len)
{
	return _ceb_first(root, kofs, CEB_KEY_TYPE, len, NULL);
}

/* return the last node or NULL if not found. */
CEB_FDECL3(struct ceb_node *, CEB_UKEY_PFX, _last, struct ceb_root *const *, root, ptrdiff_t, kofs, size_t, len)
{
	return _ceb_last(root, kofs, CEB_KEY_TYPE, len, NULL);
}

/* look up the specified key <key> of length <len>, and returns either the node
 * containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _lookup, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_lookup(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up the specified key or the highest below it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _lookup_le, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_lookup_le(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up highest key below the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _lookup_lt, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_lookup_lt(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up the specified key or the smallest above it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _lookup_ge, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_lookup_ge(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up the smallest key above the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _lookup_gt, struct ceb_root *const *, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_lookup_gt(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _next, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_next_unique(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _prev, struct ceb_root *const *, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_prev_unique(root, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up the specified node with its key and deletes it if found, and in any
 * case, returns the node. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _delete, struct ceb_root **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->CEB_KEY_MEMBER;

	return _ceb_delete(root, node, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}

/* look up the specified key, and detaches it and returns it if found, or NULL
 * if not found. The <len> field must correspond to the key length in bytes.
 */
CEB_FDECL4(struct ceb_node *, CEB_UKEY_PFX, _pick, struct ceb_root **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _ceb_delete(root, NULL, kofs, CEB_KEY_TYPE, 0, len, key, NULL);
}
