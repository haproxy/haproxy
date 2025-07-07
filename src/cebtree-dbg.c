/*
 * Compact Elastic Binary Trees - debugging functions
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


/*
 * Functions used to dump trees in Dot format.
 */
#include <stdio.h>
#include "cebtree-prv.h"

#if defined(CEB_ENABLE_DUMP)

/* Returns the xor (or the complement of the common length for strings) between
 * the two sides <l> and <r> if both are non-null, otherwise between the first
 * non-null one and the value in the associate key. As a reminder, memory
 * blocks place their length in key_u64. This is only intended for internal
 * use, essentially for debugging. It only returns zero when the keys are
 * identical, and returns a greater value for keys that are more distant.
 *
 * <kofs> contains the offset between the key and the node's base. When simply
 * adjacent, this would just be sizeof(ceb_node).
 */
static uint64_t _xor_branches(ptrdiff_t kofs, enum ceb_key_type key_type, uint32_t key_u32,
                              uint64_t key_u64, const void *key_ptr,
                              const struct ceb_root *_l,
                              const struct ceb_root *_r)
{
	const struct ceb_node *l, *r;

	l = _ceb_clrtag(_l);
	r = _ceb_clrtag(_r);

	if (l && r) {
		if (key_type == CEB_KT_MB)
			return (key_u64 << 3) - equal_bits(NODEK(l, kofs)->mb, NODEK(r, kofs)->mb, 0, key_u64 << 3);
		else if (key_type == CEB_KT_IM)
			return (key_u64 << 3) - equal_bits(NODEK(l, kofs)->mb, NODEK(r, kofs)->ptr, 0, key_u64 << 3);
		else if (key_type == CEB_KT_ST)
			return ~string_equal_bits(NODEK(l, kofs)->str, NODEK(r, kofs)->str, 0);
		else if (key_type == CEB_KT_IS)
			return ~string_equal_bits(NODEK(l, kofs)->ptr, NODEK(r, kofs)->ptr, 0);
		else if (key_type == CEB_KT_U64)
			return NODEK(l, kofs)->u64 ^ NODEK(r, kofs)->u64;
		else if (key_type == CEB_KT_U32)
			return NODEK(l, kofs)->u32 ^ NODEK(r, kofs)->u32;
		else if (key_type == CEB_KT_ADDR)
			return ((uintptr_t)l ^ (uintptr_t)r);
		else
			return 0;
	}

	if (!l)
		l = r;

	if (key_type == CEB_KT_MB)
		return (key_u64 << 3) - equal_bits(key_ptr, NODEK(l, kofs)->mb, 0, key_u64 << 3);
	else if (key_type == CEB_KT_IM)
		return (key_u64 << 3) - equal_bits(key_ptr, NODEK(l, kofs)->ptr, 0, key_u64 << 3);
	else if (key_type == CEB_KT_ST)
		return ~string_equal_bits(key_ptr, NODEK(l, kofs)->str, 0);
	else if (key_type == CEB_KT_IS)
		return ~string_equal_bits(key_ptr, NODEK(l, kofs)->ptr, 0);
	else if (key_type == CEB_KT_U64)
		return key_u64 ^ NODEK(l, kofs)->u64;
	else if (key_type == CEB_KT_U32)
		return key_u32 ^ NODEK(l, kofs)->u32;
	else if (key_type == CEB_KT_ADDR)
		return ((uintptr_t)key_ptr ^ (uintptr_t)r);
	else
		return 0;
}

/* dump the root and its link to the first node or leaf */
void ceb_imm_default_dump_root(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root, const void *ctx, int sub)
{
	const struct ceb_node *node;
	uint64_t pxor;

	if (!sub)
		printf("  \"%lx_n_%d\" [label=\"root\\n%lx\"]\n", (long)root, sub, (long)root);
	else
		printf("  \"%lx_n_%d\" [label=\"root\\n%lx\\ntree #%d\"]\n", (long)root, sub, (long)root, sub);

	node = _ceb_clrtag(*root);
	if (node) {
		/* under the root we've either a node or the first leaf */

		/* xor of the keys of the two lower branches */
		pxor = _xor_branches(kofs, key_type, 0, 0, NULL,
				     node->b[0], node->b[1]);

		printf("  \"%lx_n_%d\" -> \"%lx_%c_%d\" [label=\"B\" arrowsize=0.66%s];\n",
		       (long)root, sub, (long)node,
		       (node->b[0] == node->b[1] || !pxor) ? 'l' : 'n', sub,
		       (ctx == node) ? " color=red" : "");
	}
}

/* dump a node */
void ceb_imm_default_dump_node(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub)
{
	unsigned long long int_key = 0;
	uint64_t pxor, lxor, rxor;
	const char *str_key = NULL;

	switch (key_type) {
	case CEB_KT_ADDR:
		int_key = (uintptr_t)node;
		break;
	case CEB_KT_U32:
		int_key = NODEK(node, kofs)->u32;
		break;
	case CEB_KT_U64:
		int_key = NODEK(node, kofs)->u64;
		break;
	case CEB_KT_ST:
		str_key = (char*)NODEK(node, kofs)->str;
		break;
	case CEB_KT_IS:
		str_key = (char*)NODEK(node, kofs)->ptr;
		break;
	default:
		break;
	}

	/* xor of the keys of the two lower branches */
	pxor = _xor_branches(kofs, key_type, 0, 0, NULL,
			     node->b[0], node->b[1]);

	/* xor of the keys of the left branch's lower branches */
	lxor = _xor_branches(kofs, key_type, 0, 0, NULL,
			     (_ceb_clrtag(node->b[0])->b[0]),
			     (_ceb_clrtag(node->b[0])->b[1]));

	/* xor of the keys of the right branch's lower branches */
	rxor = _xor_branches(kofs, key_type, 0, 0, NULL,
			     (_ceb_clrtag(node->b[1])->b[0]),
			     (_ceb_clrtag(node->b[1])->b[1]));

	switch (key_type) {
	case CEB_KT_ADDR:
	case CEB_KT_U32:
	case CEB_KT_U64:
		printf("  \"%lx_n_%d\" [label=\"%lx\\nlev=%d bit=%d\\nkey=%llu\" fillcolor=\"lightskyblue1\"%s];\n",
		       (long)node, sub, (long)node, level, flsnz(pxor) - 1, int_key, (ctx == node) ? " color=red" : "");

		printf("  \"%lx_n_%d\" -> \"%lx_%c_%d\" [label=\"L\" arrowsize=0.66%s%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[0]),
		       (lxor < pxor && _ceb_clrtag(node->b[0])->b[0] != _ceb_clrtag(node->b[0])->b[1] && lxor) ? 'n' : 'l',
		       sub, (node == _ceb_clrtag(node->b[0])) ? " dir=both" : "", (ctx == _ceb_clrtag(node->b[0])) ? " color=red" : "");

		printf("  \"%lx_n_%d\" -> \"%lx_%c_%d\" [label=\"R\" arrowsize=0.66%s%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[1]),
		       (rxor < pxor && _ceb_clrtag(node->b[1])->b[0] != _ceb_clrtag(node->b[1])->b[1] && rxor) ? 'n' : 'l',
		       sub, (node == _ceb_clrtag(node->b[1])) ? " dir=both" : "", (ctx == _ceb_clrtag(node->b[1])) ? " color=red" : "");
		break;
	case CEB_KT_MB:
		break;
	case CEB_KT_IM:
		break;
	case CEB_KT_ST:
	case CEB_KT_IS:
		printf("  \"%lx_n_%d\" [label=\"%lx\\nlev=%d bit=%ld\\nkey=\\\"%s\\\"\" fillcolor=\"lightskyblue1\"%s];\n",
		       (long)node, sub, (long)node, level, (long)~pxor, str_key, (ctx == node) ? " color=red" : "");

		printf("  \"%lx_n_%d\" -> \"%lx_%c_%d\" [label=\"L\" arrowsize=0.66%s%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[0]),
		       (lxor < pxor && _ceb_clrtag(node->b[0])->b[0] != _ceb_clrtag(node->b[0])->b[1] && lxor) ? 'n' : 'l',
		       sub, (node == _ceb_clrtag(node->b[0])) ? " dir=both" : "", (ctx == _ceb_clrtag(node->b[0])) ? " color=red" : "");

		printf("  \"%lx_n_%d\" -> \"%lx_%c_%d\" [label=\"R\" arrowsize=0.66%s%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[1]),
		       (rxor < pxor && _ceb_clrtag(node->b[1])->b[0] != _ceb_clrtag(node->b[1])->b[1] && rxor) ? 'n' : 'l',
		       sub, (node == _ceb_clrtag(node->b[1])) ? " dir=both" : "", (ctx == _ceb_clrtag(node->b[1])) ? " color=red" : "");
		break;
	}
}

/* dump a duplicate entry */
void ceb_imm_default_dump_dups(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub)
{
	unsigned long long int_key = 0;
	const struct ceb_node *leaf;
	const char *str_key = NULL;
	int is_last;

	switch (key_type) {
	case CEB_KT_ADDR:
		int_key = (uintptr_t)node;
		break;
	case CEB_KT_U32:
		int_key = NODEK(node, kofs)->u32;
		break;
	case CEB_KT_U64:
		int_key = NODEK(node, kofs)->u64;
		break;
	case CEB_KT_ST:
		str_key = (char*)NODEK(node, kofs)->str;
		break;
	case CEB_KT_IS:
		str_key = (char*)NODEK(node, kofs)->ptr;
		break;
	default:
		break;
	}

	/* Let's try to determine which one is the last of the series. The
	 * right node's left node is a tree leaf in this only case. This means
	 * that node either has both sides equal to itself, or a distinct
	 * neighbours.
	 */
	leaf = _ceb_clrtag(_ceb_untag(node->b[1], 1)->b[0]);

	is_last = 1;
	if (leaf->b[0] != _ceb_dotag(leaf, 1) || leaf->b[1] != _ceb_dotag(leaf, 1))
		is_last = _xor_branches(kofs, key_type, 0, 0, NULL,
					leaf->b[0], leaf->b[1]) != 0;

	switch (key_type) {
	case CEB_KT_ADDR:
	case CEB_KT_U32:
	case CEB_KT_U64:
		printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d\\nkey=%llu\" fillcolor=\"wheat1\"%s];\n",
		       (long)node, sub, (long)node, level, int_key, (ctx == node) ? " color=red" : "");

		printf("  \"%lx_l_%d\":sw -> \"%lx_l_%d\":n [taillabel=\"L\" arrowsize=0.66%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[0]), sub, (ctx == _ceb_clrtag(node->b[0])) ? " color=red" : "");

		printf("  \"%lx_l_%d\":%s -> \"%lx_l_%d\":%s [taillabel=\"R\" arrowsize=0.66%s];\n",
		       (long)node, sub, is_last ? "se" : "ne",
		       (long)_ceb_clrtag(node->b[1]), sub, is_last ? "e" : "s", (ctx == _ceb_clrtag(node->b[1])) ? " color=red" : "");
		break;
	case CEB_KT_MB:
		break;
	case CEB_KT_IM:
		break;
	case CEB_KT_ST:
	case CEB_KT_IS:
		printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d\\nkey=\\\"%s\\\"\" fillcolor=\"wheat1\"%s];\n",
		       (long)node, sub, (long)node, level, str_key, (ctx == node) ? " color=red" : "");

		printf("  \"%lx_l_%d\":sw -> \"%lx_l_%d\":n [taillabel=\"L\" arrowsize=0.66%s];\n",
		       (long)node, sub, (long)_ceb_clrtag(node->b[0]), sub, (ctx == _ceb_clrtag(node->b[0])) ? " color=red" : "");

		printf("  \"%lx_l_%d\":%s -> \"%lx_l_%d\":%s [taillabel=\"R\" arrowsize=0.66%s];\n",
		       (long)node, sub, is_last ? "se" : "ne",
		       (long)_ceb_clrtag(node->b[1]), sub, is_last ? "e" : "s", (ctx == _ceb_clrtag(node->b[1])) ? " color=red" : "");
		break;
	}
}

/* dump a leaf */
void ceb_imm_default_dump_leaf(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub)
{
	unsigned long long int_key = 0;
	const char *str_key = NULL;
	uint64_t pxor;

	switch (key_type) {
	case CEB_KT_ADDR:
		int_key = (uintptr_t)node;
		break;
	case CEB_KT_U32:
		int_key = NODEK(node, kofs)->u32;
		break;
	case CEB_KT_U64:
		int_key = NODEK(node, kofs)->u64;
		break;
	case CEB_KT_ST:
		str_key = (char*)NODEK(node, kofs)->str;
		break;
	case CEB_KT_IS:
		str_key = (char*)NODEK(node, kofs)->ptr;
		break;
	default:
		break;
	}

	/* xor of the keys of the two lower branches */
	pxor = _xor_branches(kofs, key_type, 0, 0, NULL,
			     node->b[0], node->b[1]);

	switch (key_type) {
	case CEB_KT_ADDR:
	case CEB_KT_U32:
	case CEB_KT_U64:
		if (node->b[0] == node->b[1])
			printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d\\nkey=%llu\\n\" fillcolor=\"green\"%s];\n",
			       (long)node, sub, (long)node, level, int_key, (ctx == node) ? " color=red" : "");
		else
			printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d bit=%d\\nkey=%llu\\n\" fillcolor=\"yellow\"%s];\n",
			       (long)node, sub, (long)node, level, flsnz(pxor) - 1, int_key, (ctx == node) ? " color=red" : "");
		break;
	case CEB_KT_MB:
		break;
	case CEB_KT_IM:
		break;
	case CEB_KT_ST:
	case CEB_KT_IS:
		if (node->b[0] == node->b[1])
			printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d\\nkey=\\\"%s\\\"\\n\" fillcolor=\"green\"%s];\n",
			       (long)node, sub, (long)node, level, str_key, (ctx == node) ? " color=red" : "");
		else
			printf("  \"%lx_l_%d\" [label=\"%lx\\nlev=%d bit=%ld\\nkey=\\\"%s\\\"\\n\" fillcolor=\"yellow\"%s];\n",
			       (long)node, sub, (long)node, level, (long)~pxor, str_key, (ctx == node) ? " color=red" : "");
		break;
	}
}

/* Dumps a tree through the specified callbacks, falling back to the default
 * callbacks above if left NULL.
 */

const struct ceb_node *ceb_imm_default_dump_tree(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root,
                                             uint64_t pxor, const void *last, int level, const void *ctx, int sub,
                                             void (*root_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, struct ceb_root *const *root, const void *ctx, int sub),
                                             void (*node_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub),
                                             void (*dups_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub),
                                             void (*leaf_dump)(ptrdiff_t kofs, enum ceb_key_type key_type, const struct ceb_node *node, int level, const void *ctx, int sub))
{
	const struct ceb_node *node = _ceb_clrtag(*root);
	uint64_t xor;

	if (!node) /* empty tree */
		return node;

	if (!root_dump)
		root_dump = ceb_imm_default_dump_root;

	if (!node_dump)
		node_dump = ceb_imm_default_dump_node;

	if (!dups_dump)
		dups_dump = ceb_imm_default_dump_dups;

	if (!leaf_dump)
		leaf_dump = ceb_imm_default_dump_leaf;

	if (!level) {
		/* dump the first arrow */
		root_dump(kofs, key_type, root, ctx, sub);
	}

	/* regular nodes, all branches are canonical */

	while (1) {
		if (node->b[0] == _ceb_dotag(node, 1) && node->b[1] == _ceb_dotag(node, 1)) {
			/* first inserted leaf */
			leaf_dump(kofs, key_type, node, level, ctx, sub);
			return node;
		}

		xor = _xor_branches(kofs, key_type, 0, 0, NULL,
				    node->b[0], node->b[1]);
		if (xor)
			break;

		/* a zero XOR with different branches indicates a list element,
		 * we dump it and walk to the left until we find the node.
		 */
		dups_dump(kofs, key_type, node, level, ctx, sub);
		node = _ceb_clrtag(node->b[0]);
	}

	if (pxor && xor >= pxor) {
		/* that's a leaf */
		leaf_dump(kofs, key_type, node, level, ctx, sub);
		return node;
	}

	/* that's a regular node */
	node_dump(kofs, key_type, node, level, ctx, sub);

	last = ceb_imm_default_dump_tree(kofs, key_type, &node->b[0], xor, last, level + 1, ctx, sub, root_dump, node_dump, dups_dump, leaf_dump);
	return ceb_imm_default_dump_tree(kofs, key_type, &node->b[1], xor, last, level + 1, ctx, sub, root_dump, node_dump, dups_dump, leaf_dump);
}

#endif /* CEB_ENABLE_DUMP */
