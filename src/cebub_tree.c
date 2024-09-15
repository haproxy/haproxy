/*
 * Compact Elastic Binary Trees - exported functions operating on mb keys
 *
 * Copyright (C) 2014-2024 Willy Tarreau - w@1wt.eu
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cebtree-prv.h"

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
CEB_FDECL4(struct ceb_node *, cebub, _insert, struct ceb_node **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->mb;

	return _cebu_insert(root, node, kofs, CEB_KT_MB, 0, len, key);
}

/* return the first node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, cebub, _first, struct ceb_node **, root, ptrdiff_t, kofs)
{
	return _cebu_first(root, kofs, CEB_KT_MB);
}

/* return the last node or NULL if not found. */
CEB_FDECL2(struct ceb_node *, cebub, _last, struct ceb_node **, root, ptrdiff_t, kofs)
{
	return _cebu_last(root, kofs, CEB_KT_MB);
}

/* look up the specified key <key> of length <len>, and returns either the node
 * containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, cebub, _lookup, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_lookup(root, kofs, CEB_KT_MB, 0, len, key);
}

/* look up the specified key or the highest below it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, cebub, _lookup_le, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_lookup_le(root, kofs, CEB_KT_MB, 0, len, key);
}

/* look up highest key below the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, cebub, _lookup_lt, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_lookup_lt(root, kofs, CEB_KT_MB, 0, len, key);
}

/* look up the specified key or the smallest above it, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, cebub, _lookup_ge, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_lookup_ge(root, kofs, CEB_KT_MB, 0, len, key);
}

/* look up the smallest key above the specified one, and returns either the
 * node containing it, or NULL if not found.
 */
CEB_FDECL4(struct ceb_node *, cebub, _lookup_gt, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_lookup_gt(root, kofs, CEB_KT_MB, 0, len, key);
}

/* search for the next node after the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a left turn was made, and returning the first node along the right
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, cebub, _next, struct ceb_node **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->mb;

	return _cebu_next(root, kofs, CEB_KT_MB, 0, len, key);
}

/* search for the prev node before the specified one, and return it, or NULL if
 * not found. The approach consists in looking up that node, recalling the last
 * time a right turn was made, and returning the last node along the left
 * branch at that fork. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, cebub, _prev, struct ceb_node **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->mb;

	return _cebu_prev(root, kofs, CEB_KT_MB, 0, len, key);
}

/* look up the specified node with its key and deletes it if found, and in any
 * case, returns the node. The <len> field must correspond to the key length in
 * bytes.
 */
CEB_FDECL4(struct ceb_node *, cebub, _delete, struct ceb_node **, root, ptrdiff_t, kofs, struct ceb_node *, node, size_t, len)
{
	const void *key = NODEK(node, kofs)->mb;

	return _cebu_delete(root, node, kofs, CEB_KT_MB, 0, len, key);
}

/* look up the specified key, and detaches it and returns it if found, or NULL
 * if not found. The <len> field must correspond to the key length in bytes.
 */
CEB_FDECL4(struct ceb_node *, cebub, _pick, struct ceb_node **, root, ptrdiff_t, kofs, const void *, key, size_t, len)
{
	return _cebu_delete(root, NULL, kofs, CEB_KT_MB, 0, len, key);
}
