/*
 * Pattern management functions.
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#include <import/ebistree.h>
#include <import/ebpttree.h>
#include <import/ebsttree.h>
#include <import/lru.h>

#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/pattern.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>


const char *const pat_match_names[PAT_MATCH_NUM] = {
	[PAT_MATCH_FOUND] = "found",
	[PAT_MATCH_BOOL]  = "bool",
	[PAT_MATCH_INT]   = "int",
	[PAT_MATCH_IP]    = "ip",
	[PAT_MATCH_BIN]   = "bin",
	[PAT_MATCH_LEN]   = "len",
	[PAT_MATCH_STR]   = "str",
	[PAT_MATCH_BEG]   = "beg",
	[PAT_MATCH_SUB]   = "sub",
	[PAT_MATCH_DIR]   = "dir",
	[PAT_MATCH_DOM]   = "dom",
	[PAT_MATCH_END]   = "end",
	[PAT_MATCH_REG]   = "reg",
	[PAT_MATCH_REGM]  = "regm",
};

int (*const pat_parse_fcts[PAT_MATCH_NUM])(const char *, struct pattern *, int, char **) = {
	[PAT_MATCH_FOUND] = pat_parse_nothing,
	[PAT_MATCH_BOOL]  = pat_parse_nothing,
	[PAT_MATCH_INT]   = pat_parse_int,
	[PAT_MATCH_IP]    = pat_parse_ip,
	[PAT_MATCH_BIN]   = pat_parse_bin,
	[PAT_MATCH_LEN]   = pat_parse_int,
	[PAT_MATCH_STR]   = pat_parse_str,
	[PAT_MATCH_BEG]   = pat_parse_str,
	[PAT_MATCH_SUB]   = pat_parse_str,
	[PAT_MATCH_DIR]   = pat_parse_str,
	[PAT_MATCH_DOM]   = pat_parse_str,
	[PAT_MATCH_END]   = pat_parse_str,
	[PAT_MATCH_REG]   = pat_parse_reg,
	[PAT_MATCH_REGM]  = pat_parse_reg,
};

int (*const pat_index_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pattern *, char **) = {
	[PAT_MATCH_FOUND] = pat_idx_list_val,
	[PAT_MATCH_BOOL]  = pat_idx_list_val,
	[PAT_MATCH_INT]   = pat_idx_list_val,
	[PAT_MATCH_IP]    = pat_idx_tree_ip,
	[PAT_MATCH_BIN]   = pat_idx_list_ptr,
	[PAT_MATCH_LEN]   = pat_idx_list_val,
	[PAT_MATCH_STR]   = pat_idx_tree_str,
	[PAT_MATCH_BEG]   = pat_idx_tree_pfx,
	[PAT_MATCH_SUB]   = pat_idx_list_str,
	[PAT_MATCH_DIR]   = pat_idx_list_str,
	[PAT_MATCH_DOM]   = pat_idx_list_str,
	[PAT_MATCH_END]   = pat_idx_list_str,
	[PAT_MATCH_REG]   = pat_idx_list_reg,
	[PAT_MATCH_REGM]  = pat_idx_list_regm,
};

void (*const pat_prune_fcts[PAT_MATCH_NUM])(struct pattern_expr *) = {
	[PAT_MATCH_FOUND] = pat_prune_gen,
	[PAT_MATCH_BOOL]  = pat_prune_gen,
	[PAT_MATCH_INT]   = pat_prune_gen,
	[PAT_MATCH_IP]    = pat_prune_gen,
	[PAT_MATCH_BIN]   = pat_prune_gen,
	[PAT_MATCH_LEN]   = pat_prune_gen,
	[PAT_MATCH_STR]   = pat_prune_gen,
	[PAT_MATCH_BEG]   = pat_prune_gen,
	[PAT_MATCH_SUB]   = pat_prune_gen,
	[PAT_MATCH_DIR]   = pat_prune_gen,
	[PAT_MATCH_DOM]   = pat_prune_gen,
	[PAT_MATCH_END]   = pat_prune_gen,
	[PAT_MATCH_REG]   = pat_prune_gen,
	[PAT_MATCH_REGM]  = pat_prune_gen,
};

struct pattern *(*const pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern_expr *, int) = {
	[PAT_MATCH_FOUND] = NULL,
	[PAT_MATCH_BOOL]  = pat_match_nothing,
	[PAT_MATCH_INT]   = pat_match_int,
	[PAT_MATCH_IP]    = pat_match_ip,
	[PAT_MATCH_BIN]   = pat_match_bin,
	[PAT_MATCH_LEN]   = pat_match_len,
	[PAT_MATCH_STR]   = pat_match_str,
	[PAT_MATCH_BEG]   = pat_match_beg,
	[PAT_MATCH_SUB]   = pat_match_sub,
	[PAT_MATCH_DIR]   = pat_match_dir,
	[PAT_MATCH_DOM]   = pat_match_dom,
	[PAT_MATCH_END]   = pat_match_end,
	[PAT_MATCH_REG]   = pat_match_reg,
	[PAT_MATCH_REGM]  = pat_match_regm,
};

/* Just used for checking configuration compatibility */
int const pat_match_types[PAT_MATCH_NUM] = {
	[PAT_MATCH_FOUND] = SMP_T_SINT,
	[PAT_MATCH_BOOL]  = SMP_T_SINT,
	[PAT_MATCH_INT]   = SMP_T_SINT,
	[PAT_MATCH_IP]    = SMP_T_ADDR,
	[PAT_MATCH_BIN]   = SMP_T_BIN,
	[PAT_MATCH_LEN]   = SMP_T_STR,
	[PAT_MATCH_STR]   = SMP_T_STR,
	[PAT_MATCH_BEG]   = SMP_T_STR,
	[PAT_MATCH_SUB]   = SMP_T_STR,
	[PAT_MATCH_DIR]   = SMP_T_STR,
	[PAT_MATCH_DOM]   = SMP_T_STR,
	[PAT_MATCH_END]   = SMP_T_STR,
	[PAT_MATCH_REG]   = SMP_T_STR,
	[PAT_MATCH_REGM]  = SMP_T_STR,
};

/* this struct is used to return information */
static THREAD_LOCAL struct pattern static_pattern;
static THREAD_LOCAL struct sample_data static_sample_data;

/* This is the root of the list of all pattern_ref avalaibles. */
struct list pattern_reference = LIST_HEAD_INIT(pattern_reference);

static THREAD_LOCAL struct lru64_head *pat_lru_tree;
static unsigned long long pat_lru_seed __read_mostly;

/*
 *
 * The following functions are not exported and are used by internals process
 * of pattern matching
 *
 */

/* Background: Fast way to find a zero byte in a word
 * http://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
 * hasZeroByte = (v - 0x01010101UL) & ~v & 0x80808080UL;
 *
 * To look for 4 different byte values, xor the word with those bytes and
 * then check for zero bytes:
 *
 * v = (((unsigned char)c * 0x1010101U) ^ delimiter)
 * where <delimiter> is the 4 byte values to look for (as an uint)
 * and <c> is the character that is being tested
 */
static inline unsigned int is_delimiter(unsigned char c, unsigned int mask)
{
	mask ^= (c * 0x01010101); /* propagate the char to all 4 bytes */
	return (mask - 0x01010101) & ~mask & 0x80808080U;
}

static inline unsigned int make_4delim(unsigned char d1, unsigned char d2, unsigned char d3, unsigned char d4)
{
	return d1 << 24 | d2 << 16 | d3 << 8 | d4;
}


/*
 *
 * These functions are exported and may be used by any other component.
 *
 * The following functions are used for parsing pattern matching input value.
 * The <text> contain the string to be parsed. <pattern> must be a preallocated
 * pattern. The pat_parse_* functions fill this structure with the parsed value.
 * <err> is filled with an error message built with memprintf() function. It is
 * allowed to use a trash as a temporary storage for the returned pattern, as
 * the next call after these functions will be pat_idx_*.
 *
 * In success case, the pat_parse_* function returns 1. If the function
 * fails, it returns 0 and <err> is filled.
 */

/* ignore the current line */
int pat_parse_nothing(const char *text, struct pattern *pattern, int mflags, char **err)
{
	return 1;
}

/* Parse a string. It is allocated and duplicated. */
int pat_parse_str(const char *text, struct pattern *pattern, int mflags, char **err)
{
	pattern->type = SMP_T_STR;
	pattern->ptr.str = (char *)text;
	pattern->len = strlen(text);
	return 1;
}

/* Parse a binary written in hexa. It is allocated. */
int pat_parse_bin(const char *text, struct pattern *pattern, int mflags, char **err)
{
	struct buffer *trash;

	pattern->type = SMP_T_BIN;
	trash = get_trash_chunk();
	pattern->len = trash->size;
	pattern->ptr.str = trash->area;
	return !!parse_binary(text, &pattern->ptr.str, &pattern->len, err);
}

/* Parse a regex. It is allocated. */
int pat_parse_reg(const char *text, struct pattern *pattern, int mflags, char **err)
{
	pattern->ptr.str = (char *)text;
	return 1;
}

/* Parse a range of positive integers delimited by either ':' or '-'. If only
 * one integer is read, it is set as both min and max. An operator may be
 * specified as the prefix, among this list of 5 :
 *
 *    0:eq, 1:gt, 2:ge, 3:lt, 4:le
 *
 * The default operator is "eq". It supports range matching. Ranges are
 * rejected for other operators. The operator may be changed at any time.
 * The operator is stored in the 'opaque' argument.
 *
 * If err is non-NULL, an error message will be returned there on errors and
 * the caller will have to free it. The function returns zero on error, and
 * non-zero on success.
 *
 */
int pat_parse_int(const char *text, struct pattern *pattern, int mflags, char **err)
{
	const char *ptr = text;

	pattern->type = SMP_T_SINT;

	/* Empty string is not valid */
	if (!*text)
		goto not_valid_range;

	/* Search ':' or '-' separator. */
	while (*ptr != '\0' && *ptr != ':' && *ptr != '-')
		ptr++;

	/* If separator not found. */
	if (!*ptr) {
		if (strl2llrc(text, ptr - text, &pattern->val.range.min) != 0) {
			memprintf(err, "'%s' is not a number", text);
			return 0;
		}
		pattern->val.range.max = pattern->val.range.min;
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 1;
		return 1;
	}

	/* If the separator is the first character. */
	if (ptr == text && *(ptr + 1) != '\0') {
		if (strl2llrc(ptr + 1, strlen(ptr + 1), &pattern->val.range.max) != 0)
			goto not_valid_range;

		pattern->val.range.min_set = 0;
		pattern->val.range.max_set = 1;
		return 1;
	}

	/* If separator is the last character. */
	if (*(ptr + 1) == '\0') {
		if (strl2llrc(text, ptr - text, &pattern->val.range.min) != 0)
			goto not_valid_range;

		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 0;
		return 1;
	}

	/* Else, parse two numbers. */
	if (strl2llrc(text, ptr - text, &pattern->val.range.min) != 0)
		goto not_valid_range;

	if (strl2llrc(ptr + 1, strlen(ptr + 1), &pattern->val.range.max) != 0)
		goto not_valid_range;

	if (pattern->val.range.min > pattern->val.range.max)
		goto not_valid_range;

	pattern->val.range.min_set = 1;
	pattern->val.range.max_set = 1;
	return 1;

 not_valid_range:
	memprintf(err, "'%s' is not a valid number range", text);
	return 0;
}

/* Parse a range of positive 2-component versions delimited by either ':' or
 * '-'. The version consists in a major and a minor, both of which must be
 * smaller than 65536, because internally they will be represented as a 32-bit
 * integer.
 * If only one version is read, it is set as both min and max. Just like for
 * pure integers, an operator may be specified as the prefix, among this list
 * of 5 :
 *
 *    0:eq, 1:gt, 2:ge, 3:lt, 4:le
 *
 * The default operator is "eq". It supports range matching. Ranges are
 * rejected for other operators. The operator may be changed at any time.
 * The operator is stored in the 'opaque' argument. This allows constructs
 * such as the following one :
 *
 *    acl obsolete_ssl    ssl_req_proto lt 3
 *    acl unsupported_ssl ssl_req_proto gt 3.1
 *    acl valid_ssl       ssl_req_proto 3.0-3.1
 *
 */
int pat_parse_dotted_ver(const char *text, struct pattern *pattern, int mflags, char **err)
{
	const char *ptr = text;

	pattern->type = SMP_T_SINT;

	/* Search ':' or '-' separator. */
	while (*ptr != '\0' && *ptr != ':' && *ptr != '-')
		ptr++;

	/* If separator not found. */
	if (*ptr == '\0' && ptr > text) {
		if (strl2llrc_dotted(text, ptr-text, &pattern->val.range.min) != 0) {
			memprintf(err, "'%s' is not a dotted number", text);
			return 0;
		}
		pattern->val.range.max = pattern->val.range.min;
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 1;
		return 1;
	}

	/* If the separator is the first character. */
	if (ptr == text && *(ptr+1) != '\0') {
		if (strl2llrc_dotted(ptr+1, strlen(ptr+1), &pattern->val.range.max) != 0) {
			memprintf(err, "'%s' is not a valid dotted number range", text);
			return 0;
		}
		pattern->val.range.min_set = 0;
		pattern->val.range.max_set = 1;
		return 1;
	}

	/* If separator is the last character. */
	if (ptr == &text[strlen(text)-1]) {
		if (strl2llrc_dotted(text, ptr-text, &pattern->val.range.min) != 0) {
			memprintf(err, "'%s' is not a valid dotted number range", text);
			return 0;
		}
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 0;
		return 1;
	}

	/* Else, parse two numbers. */
	if (strl2llrc_dotted(text, ptr-text, &pattern->val.range.min) != 0) {
		memprintf(err, "'%s' is not a valid dotted number range", text);
		return 0;
	}
	if (strl2llrc_dotted(ptr+1, strlen(ptr+1), &pattern->val.range.max) != 0) {
		memprintf(err, "'%s' is not a valid dotted number range", text);
		return 0;
	}
	if (pattern->val.range.min > pattern->val.range.max) {
		memprintf(err, "'%s' is not a valid dotted number range", text);
		return 0;
	}
	pattern->val.range.min_set = 1;
	pattern->val.range.max_set = 1;
	return 1;
}

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0. NOTE: IP address patterns are typed (IPV4/IPV6).
 */
int pat_parse_ip(const char *text, struct pattern *pattern, int mflags, char **err)
{
	if (str2net(text, !(mflags & PAT_MF_NO_DNS) && (global.mode & MODE_STARTING),
	            &pattern->val.ipv4.addr, &pattern->val.ipv4.mask)) {
		pattern->type = SMP_T_IPV4;
		return 1;
	}
	else if (str62net(text, &pattern->val.ipv6.addr, &pattern->val.ipv6.mask)) {
		pattern->type = SMP_T_IPV6;
		return 1;
	}
	else {
		memprintf(err, "'%s' is not a valid IPv4 or IPv6 address", text);
		return 0;
	}
}

/*
 *
 * These functions are exported and may be used by any other component.
 *
 * This function just takes a sample <smp> and checks if this sample matches
 * with the pattern <pattern>. This function returns only PAT_MATCH or
 * PAT_NOMATCH.
 *
 */

/* always return false */
struct pattern *pat_match_nothing(struct sample *smp, struct pattern_expr *expr, int fill)
{
	if (smp->data.u.sint) {
		if (fill) {
			static_pattern.data = NULL;
			static_pattern.ref = NULL;
			static_pattern.type = 0;
			static_pattern.ptr.str = NULL;
		}
		return &static_pattern;
	}
	else
		return NULL;
}

/* ensure the input sample can be read as a string without knowing its size,
 * that is, ensure the terminating null byte is there
 *
 * The function may fail. Returns 1 on success and 0 on failure
 */
static inline int pat_match_ensure_str(struct sample *smp)
{
	if (smp->data.u.str.data < smp->data.u.str.size) {
		/* we have to force a trailing zero on the test pattern and
		 * the buffer is large enough to accommodate it. If the flag
		 * CONST is set, duplicate the string
		 */
		if (smp->flags & SMP_F_CONST) {
			if (!smp_dup(smp))
				return 0;
		} else
			smp->data.u.str.area[smp->data.u.str.data] = '\0';
	}
	else {
		/* Otherwise, the sample is duplicated. A trailing zero
		 * is automatically added to the string.
		 */
		if (!smp_dup(smp))
			return 0;
	}
	return 1;
}

/* NB: For two strings to be identical, it is required that their length match */
struct pattern *pat_match_str(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct ebmb_node *node;
	struct pattern_tree *elt;
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	/* Lookup a string in the expression's pattern tree. */
	if (!eb_is_empty(&expr->pattern_tree)) {
		if (!pat_match_ensure_str(smp))
			return NULL;

		node = ebst_lookup(&expr->pattern_tree, smp->data.u.str.area);

		while (node) {
			elt = ebmb_entry(node, struct pattern_tree, node);
			if (elt->ref->gen_id != expr->ref->curr_gen) {
				node = ebmb_next_dup(node);
				continue;
			}
			if (fill) {
				static_pattern.data = elt->data;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_STR;
				static_pattern.ptr.str = (char *)elt->node.key;
			}
			return &static_pattern;
		}
	}

	/* look in the list */
	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 20) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}


	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (pattern->len != smp->data.u.str.data)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.u.str.area, smp->data.u.str.data) == 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.u.str.area, smp->data.u.str.data) == 0)) {
			ret = pattern;
			break;
		}
	}

	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* NB: For two binaries buf to be identical, it is required that their lengths match */
struct pattern *pat_match_bin(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 20) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (pattern->len != smp->data.u.str.data)
			continue;

		if (memcmp(pattern->ptr.str, smp->data.u.str.area, smp->data.u.str.data) == 0) {
			ret = pattern;
			break;
		}
	}

	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving. This function fills
 * a matching array.
 */
struct pattern *pat_match_regm(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (regex_exec_match2(pattern->ptr.reg, smp->data.u.str.area, smp->data.u.str.data,
		                      MAX_MATCH, pmatch, 0)) {
			ret = pattern;
			smp->ctx.a[0] = pmatch;
			break;
		}
	}

	return ret;
}

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
struct pattern *pat_match_reg(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 5) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (regex_exec2(pattern->ptr.reg, smp->data.u.str.area, smp->data.u.str.data)) {
			ret = pattern;
			break;
		}
	}

	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* Checks that the pattern matches the beginning of the tested string. */
struct pattern *pat_match_beg(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct ebmb_node *node;
	struct pattern_tree *elt;
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	/* Lookup a string in the expression's pattern tree. */
	if (!eb_is_empty(&expr->pattern_tree)) {
		if (!pat_match_ensure_str(smp))
			return NULL;

		node = ebmb_lookup_longest(&expr->pattern_tree,
					   smp->data.u.str.area);

		while (node) {
			elt = ebmb_entry(node, struct pattern_tree, node);
			if (elt->ref->gen_id != expr->ref->curr_gen) {
				node = ebmb_lookup_shorter(node);
				continue;
			}
			if (fill) {
				static_pattern.data = elt->data;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_STR;
				static_pattern.ptr.str = (char *)elt->node.key;
			}
			return &static_pattern;
		}
	}

	/* look in the list */
	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 20) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (pattern->len > smp->data.u.str.data)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.u.str.area, pattern->len) != 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.u.str.area, pattern->len) != 0))
			continue;

		ret = pattern;
		break;
	}

	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* Checks that the pattern matches the end of the tested string. */
struct pattern *pat_match_end(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 20) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (pattern->len > smp->data.u.str.data)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.u.str.area + smp->data.u.str.data - pattern->len, pattern->len) != 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.u.str.area + smp->data.u.str.data - pattern->len, pattern->len) != 0))
			continue;

		ret = pattern;
		break;
	}

	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* Checks that the pattern is included inside the tested string.
 * NB: Suboptimal, should be rewritten using a Boyer-Moore method.
 */
struct pattern *pat_match_sub(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	char *end;
	char *c;
	struct pattern_list *lst;
	struct pattern *pattern;
	struct pattern *ret = NULL;
	struct lru64 *lru = NULL;

	if (pat_lru_tree && !LIST_ISEMPTY(&expr->patterns) && expr->ref->entry_cnt >= 20) {
		unsigned long long seed = pat_lru_seed ^ (long)expr;

		lru = lru64_get(XXH3(smp->data.u.str.area, smp->data.u.str.data, seed),
				pat_lru_tree, expr, expr->ref->revision);
		if (lru && lru->domain) {
			ret = lru->data;
			return ret;
		}
	}

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (pattern->len > smp->data.u.str.data)
			continue;

		end = smp->data.u.str.area + smp->data.u.str.data - pattern->len;
		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if (icase) {
			for (c = smp->data.u.str.area; c <= end; c++) {
				if (tolower((unsigned char)*c) != tolower((unsigned char)*pattern->ptr.str))
					continue;
				if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0) {
					ret = pattern;
					goto leave;
				}
			}
		} else {
			for (c = smp->data.u.str.area; c <= end; c++) {
				if (*c != *pattern->ptr.str)
					continue;
				if (strncmp(pattern->ptr.str, c, pattern->len) == 0) {
					ret = pattern;
					goto leave;
				}
			}
		}
	}
 leave:
	if (lru)
		lru64_commit(lru, ret, expr, expr->ref->revision, NULL);

	return ret;
}

/* This one is used by other real functions. It checks that the pattern is
 * included inside the tested string, but enclosed between the specified
 * delimiters or at the beginning or end of the string. The delimiters are
 * provided as an unsigned int made by make_4delim() and match up to 4 different
 * delimiters. Delimiters are stripped at the beginning and end of the pattern.
 */
static int match_word(struct sample *smp, struct pattern *pattern, int mflags, unsigned int delimiters)
{
	int may_match, icase;
	char *c, *end;
	char *ps;
	int pl;

	pl = pattern->len;
	ps = pattern->ptr.str;

	while (pl > 0 && is_delimiter(*ps, delimiters)) {
		pl--;
		ps++;
	}

	while (pl > 0 && is_delimiter(ps[pl - 1], delimiters))
		pl--;

	if (pl > smp->data.u.str.data)
		return PAT_NOMATCH;

	may_match = 1;
	icase = mflags & PAT_MF_IGNORE_CASE;
	end = smp->data.u.str.area + smp->data.u.str.data - pl;
	for (c = smp->data.u.str.area; c <= end; c++) {
		if (is_delimiter(*c, delimiters)) {
			may_match = 1;
			continue;
		}

		if (!may_match)
			continue;

		if (icase) {
			if ((tolower((unsigned char)*c) == tolower((unsigned char)*ps)) &&
			    (strncasecmp(ps, c, pl) == 0) &&
			    (c == end || is_delimiter(c[pl], delimiters)))
				return PAT_MATCH;
		} else {
			if ((*c == *ps) &&
			    (strncmp(ps, c, pl) == 0) &&
			    (c == end || is_delimiter(c[pl], delimiters)))
				return PAT_MATCH;
		}
		may_match = 0;
	}
	return PAT_NOMATCH;
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delimiters '?' or '/' or at the beginning or end of the string.
 * Delimiters at the beginning or end of the pattern are ignored.
 */
struct pattern *pat_match_dir(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (match_word(smp, pattern, expr->mflags, make_4delim('/', '?', '?', '?')))
			return pattern;
	}
	return NULL;
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delmiters '/', '?', '.' or ":" or at the beginning or end of
 * the string. Delimiters at the beginning or end of the pattern are ignored.
 */
struct pattern *pat_match_dom(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if (match_word(smp, pattern, expr->mflags, make_4delim('/', '?', '.', ':')))
			return pattern;
	}
	return NULL;
}

/* Checks that the integer in <test> is included between min and max */
struct pattern *pat_match_int(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.u.sint) &&
		    (!pattern->val.range.max_set || smp->data.u.sint <= pattern->val.range.max))
			return pattern;
	}
	return NULL;
}

/* Checks that the length of the pattern in <test> is included between min and max */
struct pattern *pat_match_len(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.u.str.data) &&
		    (!pattern->val.range.max_set || smp->data.u.str.data <= pattern->val.range.max))
			return pattern;
	}
	return NULL;
}

/* Performs ipv4 key lookup in <expr> ipv4 tree
 * Returns NULL on failure
 */
static struct pattern *_pat_match_tree_ipv4(struct in_addr *key, struct pattern_expr *expr, int fill)
{
	struct ebmb_node *node;
	struct pattern_tree *elt;

	/* Lookup an IPv4 address in the expression's pattern tree using
	 * the longest match method.
	 */
	node = ebmb_lookup_longest(&expr->pattern_tree, key);
	while (node) {
		elt = ebmb_entry(node, struct pattern_tree, node);
		if (elt->ref->gen_id != expr->ref->curr_gen) {
			node = ebmb_lookup_shorter(node);
			continue;
		}
		if (fill) {
			static_pattern.data = elt->data;
			static_pattern.ref = elt->ref;
			static_pattern.sflags = PAT_SF_TREE;
			static_pattern.type = SMP_T_IPV4;
			static_pattern.val.ipv4.addr.s_addr = read_u32(elt->node.key);
			if (!cidr2dotted(elt->node.node.pfx, &static_pattern.val.ipv4.mask))
				return NULL;
		}
		return &static_pattern;
	}
	return NULL;
}

/* Performs ipv6 key lookup in <expr> ipv6 tree
 * Returns NULL on failure
 */
static struct pattern *_pat_match_tree_ipv6(struct in6_addr *key, struct pattern_expr *expr, int fill)
{
	struct ebmb_node *node;
	struct pattern_tree *elt;

	/* Lookup an IPv6 address in the expression's pattern tree using
	 * the longest match method.
	 */
	node = ebmb_lookup_longest(&expr->pattern_tree_2, key);
	while (node) {
		elt = ebmb_entry(node, struct pattern_tree, node);
		if (elt->ref->gen_id != expr->ref->curr_gen) {
			node = ebmb_lookup_shorter(node);
			continue;
		}
		if (fill) {
			static_pattern.data = elt->data;
			static_pattern.ref = elt->ref;
			static_pattern.sflags = PAT_SF_TREE;
			static_pattern.type = SMP_T_IPV6;
			memcpy(&static_pattern.val.ipv6.addr, elt->node.key, 16);
			static_pattern.val.ipv6.mask = elt->node.node.pfx;
		}
		return &static_pattern;
	}
	return NULL;
}

struct pattern *pat_match_ip(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct in_addr v4;
	struct in6_addr v6;
	struct pattern_list *lst;
	struct pattern *pattern;

	/* The input sample is IPv4. Try to match in the trees. */
	if (smp->data.type == SMP_T_IPV4) {
		pattern = _pat_match_tree_ipv4(&smp->data.u.ipv4, expr, fill);
		if (pattern)
			return pattern;
		/* The IPv4 sample don't match the IPv4 tree. Convert the IPv4
		 * sample address to IPv6 and try to lookup in the IPv6 tree.
		 */
		v4tov6(&v6, &smp->data.u.ipv4);
		pattern = _pat_match_tree_ipv6(&v6, expr, fill);
		if (pattern)
			return pattern;
		/* eligible for list lookup using IPv4 address */
		v4 = smp->data.u.ipv4;
		goto list_lookup;
	}

	/* The input sample is IPv6. Try to match in the trees. */
	if (smp->data.type == SMP_T_IPV6) {
		pattern = _pat_match_tree_ipv6(&smp->data.u.ipv6, expr, fill);
		if (pattern)
			return pattern;
		/* No match in the IPv6 tree. Try to convert 6 to 4 to lookup in
		 * the IPv4 tree
		 */
		if (v6tov4(&v4, &smp->data.u.ipv6)) {
			pattern = _pat_match_tree_ipv4(&v4, expr, fill);
			if (pattern)
				return pattern;
			/* eligible for list lookup using IPv4 address */
			goto list_lookup;
		}
	}

 not_found:
	return NULL;

 list_lookup:
	/* No match in the trees, but we still have a valid IPv4 address: lookup
	 * in the IPv4 list (non-contiguous masks list). This is our last resort
	 */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->ref->gen_id != expr->ref->curr_gen)
			continue;

		/* Check if the input sample match the current pattern. */
		if (((v4.s_addr ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
			return pattern;
	}
	goto not_found;
}

/* finds the pattern holding <list> from list head <head> and deletes it.
 * This is made for use for pattern removal within an expression.
 */
static void pat_unlink_from_head(void **head, void **list)
{
	while (*head) {
		if (*head == list) {
			*head = *list;
			return;
		}
		head = *head;
	}
}

void free_pattern_tree(struct eb_root *root)
{
	struct eb_node *node, *next;
	struct pattern_tree *elt;

	node = eb_first(root);
	while (node) {
		next = eb_next(node);
		eb_delete(node);
		elt = container_of(node, struct pattern_tree, node);
		pat_unlink_from_head(&elt->ref->tree_head, &elt->from_ref);
		free(elt->data);
		free(elt);
		node = next;
	}
}

void pat_prune_gen(struct pattern_expr *expr)
{
	struct pattern_list *pat, *tmp;

	list_for_each_entry_safe(pat, tmp, &expr->patterns, list) {
		LIST_DELETE(&pat->list);
		pat_unlink_from_head(&pat->pat.ref->list_head, &pat->from_ref);
		if (pat->pat.sflags & PAT_SF_REGFREE)
			regex_free(pat->pat.ptr.ptr);
		else
			free(pat->pat.ptr.ptr);
		free(pat->pat.data);
		free(pat);
	}

	free_pattern_tree(&expr->pattern_tree);
	free_pattern_tree(&expr->pattern_tree_2);
	LIST_INIT(&expr->patterns);
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt = 0;
}

/*
 *
 * The following functions are used for the pattern indexation
 *
 */

int pat_idx_list_val(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	struct pattern_list *patl;

	/* allocate pattern */
	patl = calloc(1, sizeof(*patl));
	if (!patl) {
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}

	/* duplicate pattern */
	memcpy(&patl->pat, pat, sizeof(*pat));

	/* chain pattern in the expression */
	LIST_APPEND(&expr->patterns, &patl->list);
	patl->expr = expr;
	/* and from the reference */
	patl->from_ref = pat->ref->list_head;
	pat->ref->list_head = &patl->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

int pat_idx_list_ptr(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	struct pattern_list *patl;

	/* allocate pattern */
	patl = calloc(1, sizeof(*patl));
	if (!patl) {
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}

	/* duplicate pattern */
	memcpy(&patl->pat, pat, sizeof(*pat));
	patl->pat.ptr.ptr = malloc(patl->pat.len);
	if (!patl->pat.ptr.ptr) {
		free(patl);
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}
	memcpy(patl->pat.ptr.ptr, pat->ptr.ptr, pat->len);

	/* chain pattern in the expression */
	LIST_APPEND(&expr->patterns, &patl->list);
	patl->expr = expr;
	/* and from the reference */
	patl->from_ref = pat->ref->list_head;
	pat->ref->list_head = &patl->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

int pat_idx_list_str(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	struct pattern_list *patl;

	/* allocate pattern */
	patl = calloc(1, sizeof(*patl));
	if (!patl) {
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}

	/* duplicate pattern */
	memcpy(&patl->pat, pat, sizeof(*pat));
	patl->pat.ptr.str = malloc(patl->pat.len + 1);
	if (!patl->pat.ptr.str) {
		free(patl);
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}
	memcpy(patl->pat.ptr.ptr, pat->ptr.ptr, pat->len);
	patl->pat.ptr.str[patl->pat.len] = '\0';

	/* chain pattern in the expression */
	LIST_APPEND(&expr->patterns, &patl->list);
	patl->expr = expr;
	/* and from the reference */
	patl->from_ref = pat->ref->list_head;
	pat->ref->list_head = &patl->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

int pat_idx_list_reg_cap(struct pattern_expr *expr, struct pattern *pat, int cap, char **err)
{
	struct pattern_list *patl;

	/* allocate pattern */
	patl = calloc(1, sizeof(*patl));
	if (!patl) {
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}

	/* duplicate pattern */
	memcpy(&patl->pat, pat, sizeof(*pat));

	/* compile regex */
	patl->pat.sflags |= PAT_SF_REGFREE;
	if (!(patl->pat.ptr.reg = regex_comp(pat->ptr.str, !(expr->mflags & PAT_MF_IGNORE_CASE),
	                                     cap, err))) {
		free(patl);
		return 0;
	}

	/* chain pattern in the expression */
	LIST_APPEND(&expr->patterns, &patl->list);
	patl->expr = expr;
	/* and from the reference */
	patl->from_ref = pat->ref->list_head;
	pat->ref->list_head = &patl->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

int pat_idx_list_reg(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	return pat_idx_list_reg_cap(expr, pat, 0, err);
}

int pat_idx_list_regm(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	return pat_idx_list_reg_cap(expr, pat, 1, err);
}

int pat_idx_tree_ip(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	unsigned int mask;
	struct pattern_tree *node;

	/* Only IPv4 can be indexed */
	if (pat->type == SMP_T_IPV4) {
		/* in IPv4 case, check if the mask is contiguous so that we can
		 * insert the network into the tree. A continuous mask has only
		 * ones on the left. This means that this mask + its lower bit
		 * added once again is null.
		 */
		mask = ntohl(pat->val.ipv4.mask.s_addr);
		if (mask + (mask & -mask) == 0) {
			mask = mask ? 33 - flsnz(mask & -mask) : 0; /* equals cidr value */

			/* node memory allocation */
			node = calloc(1, sizeof(*node) + 4);
			if (!node) {
				memprintf(err, "out of memory while loading pattern");
				return 0;
			}

			/* copy the pointer to sample associated to this node */
			node->data = pat->data;
			node->ref = pat->ref;

			/* FIXME: insert <addr>/<mask> into the tree here */
			memcpy(node->node.key, &pat->val.ipv4.addr, 4); /* network byte order */
			node->node.node.pfx = mask;

			/* Insert the entry. */
			ebmb_insert_prefix(&expr->pattern_tree, &node->node, 4);

			node->expr = expr;
			node->from_ref = pat->ref->tree_head;
			pat->ref->tree_head = &node->from_ref;
			expr->ref->revision = rdtsc();
			expr->ref->entry_cnt++;

			/* that's ok */
			return 1;
		}
		else {
			/* If the mask is not contiguous, just add the pattern to the list */
			return pat_idx_list_val(expr, pat, err);
		}
	}
	else if (pat->type == SMP_T_IPV6) {
		/* IPv6 also can be indexed */
		node = calloc(1, sizeof(*node) + 16);
		if (!node) {
			memprintf(err, "out of memory while loading pattern");
			return 0;
		}

		/* copy the pointer to sample associated to this node */
		node->data = pat->data;
		node->ref = pat->ref;

		/* FIXME: insert <addr>/<mask> into the tree here */
		memcpy(node->node.key, &pat->val.ipv6.addr, 16); /* network byte order */
		node->node.node.pfx = pat->val.ipv6.mask;

		/* Insert the entry. */
		ebmb_insert_prefix(&expr->pattern_tree_2, &node->node, 16);

		node->expr = expr;
		node->from_ref = pat->ref->tree_head;
		pat->ref->tree_head = &node->from_ref;
		expr->ref->revision = rdtsc();
		expr->ref->entry_cnt++;

		/* that's ok */
		return 1;
	}

	return 0;
}

int pat_idx_tree_str(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	int len;
	struct pattern_tree *node;

	/* Only string can be indexed */
	if (pat->type != SMP_T_STR) {
		memprintf(err, "internal error: string expected, but the type is '%s'",
		          smp_to_type[pat->type]);
		return 0;
	}

	/* If the flag PAT_F_IGNORE_CASE is set, we cannot use trees */
	if (expr->mflags & PAT_MF_IGNORE_CASE)
		return pat_idx_list_str(expr, pat, err);

	/* Process the key len */
	len = strlen(pat->ptr.str) + 1;

	/* node memory allocation */
	node = calloc(1, sizeof(*node) + len);
	if (!node) {
		memprintf(err, "out of memory while loading pattern");
		return 0;
	}

	/* copy the pointer to sample associated to this node */
	node->data = pat->data;
	node->ref = pat->ref;

	/* copy the string */
	memcpy(node->node.key, pat->ptr.str, len);

	/* index the new node */
	ebst_insert(&expr->pattern_tree, &node->node);

	node->expr = expr;
	node->from_ref = pat->ref->tree_head;
	pat->ref->tree_head = &node->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

int pat_idx_tree_pfx(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	int len;
	struct pattern_tree *node;

	/* Only string can be indexed */
	if (pat->type != SMP_T_STR) {
		memprintf(err, "internal error: string expected, but the type is '%s'",
		          smp_to_type[pat->type]);
		return 0;
	}

	/* If the flag PAT_F_IGNORE_CASE is set, we cannot use trees */
	if (expr->mflags & PAT_MF_IGNORE_CASE)
		return pat_idx_list_str(expr, pat, err);

	/* Process the key len */
	len = strlen(pat->ptr.str);

	/* node memory allocation */
	node = calloc(1, sizeof(*node) + len + 1);
	if (!node) {
		memprintf(err, "out of memory while loading pattern");
		return 0;
	}

	/* copy the pointer to sample associated to this node */
	node->data = pat->data;
	node->ref = pat->ref;

	/* copy the string and the trailing zero */
	memcpy(node->node.key, pat->ptr.str, len + 1);
	node->node.node.pfx = len * 8;

	/* index the new node */
	ebmb_insert_prefix(&expr->pattern_tree, &node->node, len);

	node->expr = expr;
	node->from_ref = pat->ref->tree_head;
	pat->ref->tree_head = &node->from_ref;
	expr->ref->revision = rdtsc();
	expr->ref->entry_cnt++;

	/* that's ok */
	return 1;
}

/* Deletes all patterns from reference <elt>. Note that all of their
 * expressions must be locked, and the pattern lock must be held as well.
 */
void pat_delete_gen(struct pat_ref *ref, struct pat_ref_elt *elt)
{
	struct pattern_tree *tree;
	struct pattern_list *pat;
	void **node;

	/* delete all known tree nodes. They are all allocated inline */
	for (node = elt->tree_head; node;) {
		tree = container_of(node, struct pattern_tree, from_ref);
		node = *node;
		BUG_ON(tree->ref != elt);

		ebmb_delete(&tree->node);
		free(tree->data);
		free(tree);
	}

	/* delete all list nodes and free their pattern entries (str/reg) */
	for (node = elt->list_head; node;) {
		pat = container_of(node, struct pattern_list, from_ref);
		node = *node;
		BUG_ON(pat->pat.ref != elt);

		/* Delete and free entry. */
		LIST_DELETE(&pat->list);
		if (pat->pat.sflags & PAT_SF_REGFREE)
			regex_free(pat->pat.ptr.reg);
		else
			free(pat->pat.ptr.ptr);
		free(pat->pat.data);
		free(pat);
	}

	/* update revision number to refresh the cache */
	ref->revision = rdtsc();
	ref->entry_cnt--;
	elt->tree_head = NULL;
	elt->list_head = NULL;
}

void pattern_init_expr(struct pattern_expr *expr)
{
	LIST_INIT(&expr->patterns);
	expr->pattern_tree = EB_ROOT;
	expr->pattern_tree_2 = EB_ROOT;
}

void pattern_init_head(struct pattern_head *head)
{
	LIST_INIT(&head->head);
}

/* The following functions are relative to the management of the reference
 * lists. These lists are used to store the original pattern and associated
 * value as string form.
 *
 * This is used with modifiable ACL and MAPS
 *
 * The pattern reference are stored with two identifiers: the unique_id and
 * the reference.
 *
 * The reference identify a file. Each file with the same name point to the
 * same reference. We can register many times one file. If the file is modified,
 * all his dependencies are also modified. The reference can be used with map or
 * acl.
 *
 * The unique_id identify inline acl. The unique id is unique for each acl.
 * You cannot force the same id in the configuration file, because this repoort
 * an error.
 *
 * A particular case appears if the filename is a number. In this case, the
 * unique_id is set with the number represented by the filename and the
 * reference is also set. This method prevent double unique_id.
 *
 */

/* This function looks up a reference by name. If the reference is found, a
 * pointer to the struct pat_ref is returned, otherwise NULL is returned.
 */
struct pat_ref *pat_ref_lookup(const char *reference)
{
	struct pat_ref *ref;

	/* Skip file@ prefix, it is the default case. Can be mixed with ref omitting the prefix */
	if (strlen(reference) > 5 && strncmp(reference, "file@", 5) == 0)
		reference += 5;

	list_for_each_entry(ref, &pattern_reference, list)
		if (ref->reference && strcmp(reference, ref->reference) == 0)
			return ref;
	return NULL;
}

/* This function looks up a reference's unique id. If the reference is found, a
 * pointer to the struct pat_ref is returned, otherwise NULL is returned.
 */
struct pat_ref *pat_ref_lookupid(int unique_id)
{
	struct pat_ref *ref;

	list_for_each_entry(ref, &pattern_reference, list)
		if (ref->unique_id == unique_id)
			return ref;
	return NULL;
}

/* This function removes from the pattern reference <ref> all the patterns
 * attached to the reference element <elt>, and the element itself. The
 * reference must be locked.
 */
void pat_ref_delete_by_ptr(struct pat_ref *ref, struct pat_ref_elt *elt)
{
	struct pattern_expr *expr;
	struct bref *bref, *back;

	/*
	 * we have to unlink all watchers from this reference pattern. We must
	 * not relink them if this elt was the last one in the list.
	 */
	list_for_each_entry_safe(bref, back, &elt->back_refs, users) {
		LIST_DELETE(&bref->users);
		LIST_INIT(&bref->users);
		if (elt->list.n != &ref->head)
			LIST_APPEND(&LIST_ELEM(elt->list.n, typeof(elt), list)->back_refs, &bref->users);
		bref->ref = elt->list.n;
	}

	/* delete all entries from all expressions for this pattern */
	list_for_each_entry(expr, &ref->pat, list)
		HA_RWLOCK_WRLOCK(PATEXP_LOCK, &expr->lock);

	pat_delete_gen(ref, elt);

	list_for_each_entry(expr, &ref->pat, list)
		HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);

	LIST_DELETE(&elt->list);
	ebmb_delete(&elt->node);
	free(elt->sample);
	free(elt);
}

/* This function removes the pattern matching the pointer <refelt> from
 * the reference and from each expr member of this reference. This function
 * returns 1 if the entry was found and deleted, otherwise zero.
 *
 * <refelt> is user input: it is provided as an ID and should never be
 * dereferenced without making sure that it is valid.
 */
int pat_ref_delete_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt)
{
	struct pat_ref_elt *elt, *safe;

	/* delete pattern from reference */
	list_for_each_entry_safe(elt, safe, &ref->head, list) {
		if (elt == refelt) {
			event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_DEL, NULL);
			pat_ref_delete_by_ptr(ref, elt);
			return 1;
		}
	}
	return 0;
}

/* This function removes all elements belonging to <gen_id> and matching <key>
 * from the reference <ref>.
 * This function returns 1 if the deletion is done and returns 0 if
 * the entry is not found.
 */
int pat_ref_gen_delete(struct pat_ref *ref, unsigned int gen_id, const char *key)
{
	struct ebmb_node *node;
	int found = 0;

	/* delete pattern from reference */
	node = ebst_lookup(&ref->ebmb_root, key);
	while (node) {
		struct pat_ref_elt *elt;

		elt = ebmb_entry(node, struct pat_ref_elt, node);
		node = ebmb_next_dup(node);
		if (elt->gen_id != gen_id)
			continue;
		pat_ref_delete_by_ptr(ref, elt);
		found = 1;
	}

	if (found)
		event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_DEL, NULL);

	return found;
}

/* This function removes all patterns matching <key> from the reference
 * and from each expr member of the reference. This function returns 1
 * if the deletion is done and returns 0 is the entry is not found.
 */
int pat_ref_delete(struct pat_ref *ref, const char *key)
{
	return pat_ref_gen_delete(ref, ref->curr_gen, key);
}

/*
 * find and return an element <elt> belonging to <gen_id> and matching <key> in a
 * reference <ref> return NULL if not found
 */
struct pat_ref_elt *pat_ref_gen_find_elt(struct pat_ref *ref, unsigned int gen_id, const char *key)
{
	struct ebmb_node *node;
	struct pat_ref_elt *elt;

	node = ebst_lookup(&ref->ebmb_root, key);
	while (node) {
		elt = ebmb_entry(node, struct pat_ref_elt, node);
		if (elt->gen_id == gen_id)
			break;
		node = ebmb_next_dup(node);
	}
	if (node)
		return ebmb_entry(node, struct pat_ref_elt, node);

	return NULL;
}

/*
 * find and return an element <elt> matching <key> in a reference <ref>
 * return NULL if not found
 */
struct pat_ref_elt *pat_ref_find_elt(struct pat_ref *ref, const char *key)
{
	return pat_ref_gen_find_elt(ref, ref->curr_gen, key);
}


/* This function modifies the sample of pat_ref_elt <elt> in all expressions
 * found under <ref> to become <value>. It is assumed that the caller has
 * already verified that <elt> belongs to <ref>.
 */
static inline int pat_ref_set_elt(struct pat_ref *ref, struct pat_ref_elt *elt,
                                  const char *value, char **err)
{
	struct pattern_expr *expr;
	struct sample_data **data;
	char *sample;
	struct sample_data test;
	struct pattern_tree *tree;
	struct pattern_list *pat;
	void **node;


	/* Try all needed converters. */
	list_for_each_entry(expr, &ref->pat, list) {
		if (!expr->pat_head->parse_smp)
			continue;

		if (!expr->pat_head->parse_smp(value, &test)) {
			memprintf(err, "unable to parse '%s'", value);
			return 0;
		}
	}

	/* Modify pattern from reference. */
	sample = strdup(value);
	if (!sample) {
		memprintf(err, "out of memory error");
		return 0;
	}
	/* Load sample in each reference. All the conversions are tested
	 * below, normally these calls don't fail.
	 */
	for (node = elt->tree_head; node;) {
		tree = container_of(node, struct pattern_tree, from_ref);
		node = *node;
		BUG_ON(tree->ref != elt);
		expr = tree->expr;
		if (!expr->pat_head->parse_smp)
			continue;

		data = &tree->data;
		if (data && *data) {
			HA_RWLOCK_WRLOCK(PATEXP_LOCK, &expr->lock);
			if (!expr->pat_head->parse_smp(sample, *data))
				*data = NULL;
			HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);
		}
	}

	for (node = elt->list_head; node;) {
		pat = container_of(node, struct pattern_list, from_ref);
		node = *node;
		BUG_ON(pat->pat.ref != elt);
		expr = pat->expr;
		if (!expr->pat_head->parse_smp)
			continue;

		data = &pat->pat.data;
		if (data && *data) {
			HA_RWLOCK_WRLOCK(PATEXP_LOCK, &expr->lock);
			if (!expr->pat_head->parse_smp(sample, *data))
				*data = NULL;
			HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);
		}
	}

	/* free old sample only when all exprs are updated */
	free(elt->sample);
	elt->sample = sample;


	return 1;
}

/* This function modifies the sample of pat_ref_elt <refelt> in all expressions
 * found under <ref> to become <value>, after checking that <refelt> really
 * belongs to <ref>.
 *
 * <refelt> is user input: it is provided as an ID and should never be
 * dereferenced without making sure that it is valid.
 */
int pat_ref_set_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt, const char *value, char **err)
{
	struct pat_ref_elt *elt;

	/* Look for pattern in the reference. */
	list_for_each_entry(elt, &ref->head, list) {
		if (elt == refelt) {
			if (!pat_ref_set_elt(ref, elt, value, err))
				return 0;
			return 1;
		}
	}

	memprintf(err, "key or pattern not found");
	return 0;
}

static int pat_ref_set_from_node(struct pat_ref *ref, struct ebmb_node *node, const char *value, char **err)
{
	struct pat_ref_elt *elt;
	unsigned int gen;
	int first = 1;
	int found = 0;

	while (node) {
		char *tmp_err = NULL;

		elt = ebmb_entry(node, struct pat_ref_elt, node);
		if (first)
			gen = elt->gen_id;
		else if (elt->gen_id != gen) {
			/* only consider duplicate elements from the same gen! */
			continue;
		}
		node = ebmb_next_dup(node);
		if (!pat_ref_set_elt(ref, elt, value, &tmp_err)) {
			if (err)
				*err = tmp_err;
			else
				ha_free(&tmp_err);
			return 0;
		}
		found = 1;
		first = 0;
	}

	if (!found) {
		memprintf(err, "entry not found");
		return 0;
	}

	if (gen == ref->curr_gen) // gen cannot be uninitialized here
		event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_SET, NULL);

	return 1;
}

/* modifies to <value> the sample for <elt> and all its duplicates */
int pat_ref_set_elt_duplicate(struct pat_ref *ref, struct pat_ref_elt *elt, const char *value,
                              char **err)
{
	return pat_ref_set_from_node(ref, &elt->node, value, err);
}

/* This function modifies to <value> the sample of all patterns matching <key>
 * and belonging to <gen_id> under <ref>.
 */
int pat_ref_gen_set(struct pat_ref *ref, unsigned int gen_id,
                    const char *key, const char *value, char **err)
{
	struct ebmb_node *node;
	struct pat_ref_elt *elt;

	/* Look for pattern in the reference. */
	node = ebst_lookup(&ref->ebmb_root, key);
	while (node) {
		elt = ebmb_entry(node, struct pat_ref_elt, node);
		if (elt->gen_id == gen_id)
			break;
		node = ebmb_next_dup(node);
	}
	return pat_ref_set_from_node(ref, node, value, err);
}

/* This function modifies to <value> the sample of all patterns matching <key>
 * under <ref>.
 */
int pat_ref_set(struct pat_ref *ref, const char *key, const char *value, char **err)
{
	return pat_ref_gen_set(ref, ref->curr_gen, key, value, err);
}

/* helper function to create and initialize a generic pat_ref struct
 *
 * Returns the new struct on success and NULL on failure (memory allocation
 * error)
 */
static struct pat_ref *_pat_ref_new(const char *display, unsigned int flags)
{
	struct pat_ref *ref;

	ref = malloc(sizeof(*ref));
	if (!ref)
		return NULL;

	/* don't forget to explicitly initialize all pat_ref struct members */

	if (display) {
		ref->display = strdup(display);
		if (!ref->display) {
			free(ref);
			return NULL;
		}
	}

	ref->reference = NULL;
	ref->flags = flags;
	ref->curr_gen = 0;
        ref->next_gen = 0;
	ref->unique_id = -1;
	ref->revision = 0;
	ref->entry_cnt = 0;
	LIST_INIT(&ref->head);
	ref->ebmb_root = EB_ROOT;
	LIST_INIT(&ref->pat);
	HA_RWLOCK_INIT(&ref->lock);
	event_hdl_sub_list_init(&ref->e_subs);

	return ref;
}

/* helper func to properly de-initialize and free pat_ref struct */
static void pat_ref_free(struct pat_ref *ref)
{
	ha_free(&ref->reference);
	ha_free(&ref->display);
	event_hdl_sub_list_destroy(&ref->e_subs);
	free(ref);
}

/* This function creates a new reference. <ref> is the reference name.
 * <flags> are PAT_REF_*. /!\ The reference is not checked, and must
 * be unique. The user must check the reference with "pat_ref_lookup()"
 * before calling this function. If the function fails, it returns NULL,
 * otherwise it returns the new struct pat_ref.
 */
struct pat_ref *pat_ref_new(const char *reference, const char *display, unsigned int flags)
{
	struct pat_ref *ref;

	ref = _pat_ref_new(display, flags);
	if (!ref)
		return NULL;

	if (strlen(reference) > 5 && strncmp(reference, "virt@", 5) == 0)
		ref->flags |= PAT_REF_ID;
	else if (strlen(reference) > 4 && strncmp(reference, "opt@", 4) == 0) {
		ref->flags |= (PAT_REF_ID|PAT_REF_FILE); // Will be decided later
		reference += 4;
	}
	else {
		/* A file by default */
		ref->flags |= PAT_REF_FILE;
		/* Skip file@ prefix to be mixed with ref omitting the prefix */
		if (strlen(reference) > 5 && strncmp(reference, "file@", 5) == 0)
			reference += 5;
	}


	ref->reference = strdup(reference);
	if (!ref->reference) {
		pat_ref_free(ref);
		return NULL;
	}

	LIST_APPEND(&pattern_reference, &ref->list);
	return ref;
}

/* This function creates a new reference. <unique_id> is the unique id. If
 * the value of <unique_id> is -1, the unique id is calculated later.
 * <flags> are PAT_REF_*. /!\ The reference is not checked, and must
 * be unique. The user must check the reference with "pat_ref_lookup()"
 * or pat_ref_lookupid before calling this function. If the function
 * fails, it returns NULL, otherwise it returns the new struct pat_ref.
 */
struct pat_ref *pat_ref_newid(int unique_id, const char *display, unsigned int flags)
{
	struct pat_ref *ref;

	ref = _pat_ref_new(display, flags);
	if (!ref)
		return NULL;

	ref->unique_id = unique_id;

	LIST_APPEND(&pattern_reference, &ref->list);
	return ref;
}

/* This function adds entry to <ref>. It can fail on memory error. It returns
 * the newly added element on success, or NULL on failure. The PATREF_LOCK on
 * <ref> must be held. It sets the newly created pattern's generation number
 * to the same value as the reference's.
 */
struct pat_ref_elt *pat_ref_append(struct pat_ref *ref, const char *pattern, const char *sample, int line)
{
	struct pat_ref_elt *elt;
	int len = strlen(pattern);

	elt = calloc(1, sizeof(*elt) + len + 1);
	if (!elt)
		goto fail;

	elt->gen_id = ref->curr_gen;
	elt->line = line;

	memcpy((char*)elt->pattern, pattern, len + 1);

	if (sample) {
		elt->sample = strdup(sample);
		if (!elt->sample)
			goto fail;
	}

	LIST_INIT(&elt->back_refs);
	elt->list_head = NULL;
	elt->tree_head = NULL;
	LIST_APPEND(&ref->head, &elt->list);
	/* Even if calloc()'ed, ensure this node is not linked to a tree. */
	elt->node.node.leaf_p = NULL;
	ebst_insert(&ref->ebmb_root, &elt->node);
	return elt;
 fail:
	free(elt);
	return NULL;
}

/* This function creates sample found in <elt>, parses the pattern also
 * found in <elt> and inserts it in <expr>. The function copies <patflags>
 * into <expr>. If the function fails, it returns 0 and <err> is filled.
 * In success case, the function returns 1.
 */
int pat_ref_push(struct pat_ref_elt *elt, struct pattern_expr *expr,
                 int patflags, char **err)
{
	struct sample_data *data;
	struct pattern pattern;

	/* Create sample */
	if (elt->sample && expr->pat_head->parse_smp) {
		/* New sample. */
		data = malloc(sizeof(*data));
		if (!data)
			return 0;

		/* Parse value. */
		if (!expr->pat_head->parse_smp(elt->sample, data)) {
			memprintf(err, "unable to parse '%s'", elt->sample);
			free(data);
			return 0;
		}

	}
	else
		data = NULL;

	/* initialise pattern */
	memset(&pattern, 0, sizeof(pattern));
	pattern.data = data;
	pattern.ref = elt;

	/* parse pattern */
	if (!expr->pat_head->parse(elt->pattern, &pattern, expr->mflags, err)) {
		free(data);
		return 0;
	}

	HA_RWLOCK_WRLOCK(PATEXP_LOCK, &expr->lock);
	/* index pattern */
	if (!expr->pat_head->index(expr, &pattern, err)) {
		HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);
		free(data);
		return 0;
	}
	HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);

	return 1;
}

/* This function tries to commit entry <elt> into <ref>. The new entry must
 * have already been inserted using pat_ref_append(), and its generation number
 * may have been adjusted as it will not be changed. <err> must point to a NULL
 * pointer. The PATREF lock on <ref> must be held. All the pattern_expr for
 * this reference will be updated (parsing, indexing). On success, non-zero is
 * returned. On failure, all the operation is rolled back (the element is
 * deleted from all expressions and is freed), zero is returned and the error
 * pointer <err> may have been updated (and the caller must free it). Failure
 * causes include memory allocation, parsing error or indexing error.
 */
int pat_ref_commit_elt(struct pat_ref *ref, struct pat_ref_elt *elt, char **err)
{
	struct pattern_expr *expr;

	list_for_each_entry(expr, &ref->pat, list) {
		if (!pat_ref_push(elt, expr, 0, err)) {
			pat_ref_delete_by_ptr(ref, elt);
			return 0;
		}
	}
	return 1;
}

/* Loads <pattern>:<sample> into <ref> for generation <gen>. <sample> may be
 * NULL if none exists (e.g. ACL). If not needed, the generation number should
 * be set to ref->curr_gen. The error pointer must initially point to NULL. The
 * new entry will be propagated to all use places, involving allocation, parsing
 * and indexing. On error (parsing, allocation), the operation will be rolled
 * back, an error may be reported, and NULL will be reported. On success, the
 * freshly allocated element will be returned. The PATREF lock on <ref> must be
 * held during the operation.
 */
struct pat_ref_elt *pat_ref_load(struct pat_ref *ref, unsigned int gen,
                                 const char *pattern, const char *sample,
                                 int line, char **err)
{
	struct pat_ref_elt *elt;

	elt = pat_ref_append(ref, pattern, sample, line);
	if (elt) {
		elt->gen_id = gen;
		if (!pat_ref_commit_elt(ref, elt, err))
			elt = NULL;
	} else
		memprintf(err, "out of memory error");

	/* ignore if update requires committing to be seen */
	if (elt && gen == ref->curr_gen)
		event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_ADD, NULL);

	return elt;
}

/* This function adds entry to <ref>. It can fail on memory error. The new
 * entry is added at all the pattern_expr registered in this reference. The
 * function stops on the first error encountered. It returns 0 and <err> is
 * filled. If an error is encountered, the complete add operation is cancelled.
 * If the insertion is a success the function returns 1.
 */
int pat_ref_add(struct pat_ref *ref,
                const char *pattern, const char *sample,
                char **err)
{
	return !!pat_ref_load(ref, ref->curr_gen, pattern, sample, -1, err);
}

/* This function purges all elements from <ref> whose generation is included in
 * the range of <from> to <to> (inclusive), taking wrapping into consideration.
 * It will not purge more than <budget> entries at once, in order to remain
 * responsive. If budget is negative, no limit is applied.
 * The caller must already hold the PATREF_LOCK on <ref>. The function will
 * take the PATEXP_LOCK on all expressions of the pattern as needed. It returns
 * non-zero on completion, or zero if it had to stop before the end after
 * <budget> was depleted.
 */
int pat_ref_purge_range(struct pat_ref *ref, uint from, uint to, int budget)
{
	struct pat_ref_elt *elt, *elt_bck;
	struct bref *bref, *bref_bck;
	struct pattern_expr *expr;
	int done;

	list_for_each_entry(expr, &ref->pat, list)
		HA_RWLOCK_WRLOCK(PATEXP_LOCK, &expr->lock);

	/* all expr are locked, we can safely remove all pat_ref */

	/* assume completion for e.g. empty lists */
	done = 1;
	list_for_each_entry_safe(elt, elt_bck, &ref->head, list) {
		if (elt->gen_id - from > to - from)
			continue;

		if (budget >= 0 && !budget--) {
			done = 0;
			break;
		}

		/*
		 * we have to unlink all watchers from this reference pattern. We must
		 * not relink them if this elt was the last one in the list.
		 */
		list_for_each_entry_safe(bref, bref_bck, &elt->back_refs, users) {
			LIST_DELETE(&bref->users);
			LIST_INIT(&bref->users);
			if (elt->list.n != &ref->head)
				LIST_APPEND(&LIST_ELEM(elt->list.n, typeof(elt), list)->back_refs, &bref->users);
			bref->ref = elt->list.n;
		}

		/* delete the storage for all representations of this pattern. */
		pat_delete_gen(ref, elt);

		LIST_DELETE(&elt->list);
		ebmb_delete(&elt->node);
		free(elt->sample);
		free(elt);
	}

	list_for_each_entry(expr, &ref->pat, list)
		HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &expr->lock);

	/* only publish when we're done and if curr_gen was impacted by the
	 * purge
	 */
	if (done && ref->curr_gen - from <= to - from)
		event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_CLEAR, NULL);

	return done;
}

/* This function prunes all entries of <ref> and all their associated
 * pattern_expr. It may return before the end of the list is reached,
 * returning 0, to yield, indicating to the caller that it must call it again.
 * until it returns non-zero. All patterns are purged, both current ones and
 * future or incomplete ones. This is used by "clear map" or "clear acl".
 */
int pat_ref_prune(struct pat_ref *ref)
{
	return pat_ref_purge_range(ref, 0, ~0, 100);
}

/* This function looks up any existing reference <ref> in pattern_head <head>, and
 * returns the associated pattern_expr pointer if found, otherwise NULL.
 */
struct pattern_expr *pattern_lookup_expr(struct pattern_head *head, struct pat_ref *ref)
{
	struct pattern_expr_list *expr;

	list_for_each_entry(expr, &head->head, list)
		if (expr->expr->ref == ref)
			return expr->expr;
	return NULL;
}

/* This function creates new pattern_expr associated to the reference <ref>.
 * <ref> can be NULL. If an error occurs, the function returns NULL and
 * <err> is filled. Otherwise, the function returns new pattern_expr linked
 * with <head> and <ref>.
 *
 * The returned value can be an already filled pattern list, in this case the
 * flag <reuse> is set.
 */
struct pattern_expr *pattern_new_expr(struct pattern_head *head, struct pat_ref *ref,
                                      int patflags, char **err, int *reuse)
{
	struct pattern_expr *expr;
	struct pattern_expr_list *list;

	if (reuse)
		*reuse = 0;

	/* Memory and initialization of the chain element. */
	list = calloc(1, sizeof(*list));
	if (!list) {
		memprintf(err, "out of memory");
		return NULL;
	}

	/* Look for existing similar expr. No that only the index, parse and
	 * parse_smp function must be identical for having similar pattern.
	 * The other function depends of these first.
	 */
	if (ref) {
		list_for_each_entry(expr, &ref->pat, list)
			if (expr->pat_head->index     == head->index &&
			    expr->pat_head->parse     == head->parse &&
			    expr->pat_head->parse_smp == head->parse_smp &&
			    expr->mflags == patflags)
				break;
		if (&expr->list == &ref->pat)
			expr = NULL;
	}
	else
		expr = NULL;

	/* If no similar expr was found, we create new expr. */
	if (!expr) {
		/* Get a lot of memory for the expr struct. */
		expr = calloc(1, sizeof(*expr));
		if (!expr) {
			free(list);
			memprintf(err, "out of memory");
			return NULL;
		}

		/* Initialize this new expr. */
		pattern_init_expr(expr);

		/* Copy the pattern matching and indexing flags. */
		expr->mflags = patflags;

		/* This new pattern expression reference one of his heads. */
		expr->pat_head = head;

		/* Link with ref, or to self to facilitate LIST_DELETE() */
		if (ref)
			LIST_APPEND(&ref->pat, &expr->list);
		else
			LIST_INIT(&expr->list);

		expr->ref = ref;

		HA_RWLOCK_INIT(&expr->lock);
	}
	else {
		if (reuse)
			*reuse = 1;
	}

	HA_ATOMIC_INC(&expr->refcount);

	/* The new list element reference the pattern_expr. */
	list->expr = expr;

	/* Link the list element with the pattern_head. */
	LIST_APPEND(&head->head, &list->list);
	return expr;
}

/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 *
 * The file contains one key + value per line. Lines which start with '#' are
 * ignored, just like empty lines. Leading tabs/spaces are stripped. The key is
 * then the first "word" (series of non-space/tabs characters), and the value is
 * what follows this series of space/tab till the end of the line excluding
 * trailing spaces/tabs.
 *
 * Example :
 *
 *     # this is a comment and is ignored
 *        62.212.114.60     1wt.eu      \n
 *     <-><-----------><---><----><---->
 *      |       |        |     |     `--- trailing spaces ignored
 *      |       |        |      `-------- value
 *      |       |        `--------------- middle spaces ignored
 *      |       `------------------------ key
 *      `-------------------------------- leading spaces ignored
 *
 * Return non-zero in case of success, otherwise 0.
 */
int pat_ref_read_from_file_smp(struct pat_ref *ref, char **err)
{
	FILE *file;
	char *c;
	int ret = 0;
	int line = 0;
	char *key_beg;
	char *key_end;
	char *value_beg;
	char *value_end;

	file = fopen(ref->reference, "r");
	if (!file) {
		if (ref->flags & PAT_REF_ID) {
			/* file not found for an optional file, switch it to a virtual list of patterns */
			ref->flags &= ~PAT_REF_FILE;
			return 1;
		}
		memprintf(err, "failed to open pattern file <%s>", ref->reference);
		return 0;
	}
	ref->flags |= PAT_REF_FILE;

	/* now parse all patterns. The file may contain only one pattern
	 * followed by one value per line. The start spaces, separator spaces
	 * and and spaces are stripped. Each can contain comment started by '#'
	 */
	while (fgets(trash.area, trash.size, file) != NULL) {
		line++;
		c = trash.area;

		/* ignore lines beginning with a dash */
		if (*c == '#')
			continue;

		/* strip leading spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* empty lines are ignored too */
		if (*c == '\0' || *c == '\r' || *c == '\n')
			continue;

		/* look for the end of the key */
		key_beg = c;
		while (*c && *c != ' ' && *c != '\t' && *c != '\n' && *c != '\r')
			c++;

		key_end = c;

		/* strip middle spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* look for the end of the value, it is the end of the line */
		value_beg = c;
		while (*c && *c != '\n' && *c != '\r')
			c++;
		value_end = c;

		/* trim possibly trailing spaces and tabs */
		while (value_end > value_beg && (value_end[-1] == ' ' || value_end[-1] == '\t'))
			value_end--;

		/* set final \0 and check entries */
		*key_end = '\0';
		*value_end = '\0';

		/* insert values */
		if (!pat_ref_append(ref, key_beg, value_beg, line)) {
			memprintf(err, "out of memory");
			goto out_close;
		}
	}

	if (ferror(file)) {
		memprintf(err, "error encountered while reading  <%s> : %s",
				ref->reference, strerror(errno));
		goto out_close;
	}
	/* success */
	ret = 1;

 out_close:
	fclose(file);
	return ret;
}

/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 */
int pat_ref_read_from_file(struct pat_ref *ref, char **err)
{
	FILE *file;
	char *c;
	char *arg;
	int ret = 0;
	int line = 0;

	file = fopen(ref->reference, "r");
	if (!file) {
		if (ref->flags & PAT_REF_ID) {
			/* file not found for an optional file, switch it to a virtual list of patterns */
			ref->flags &= ~PAT_REF_FILE;
			return 1;
		}
		memprintf(err, "failed to open pattern file <%s>", ref->reference);
		return 0;
	}

	/* now parse all patterns. The file may contain only one pattern per
	 * line. If the line contains spaces, they will be part of the pattern.
	 * The pattern stops at the first CR, LF or EOF encountered.
	 */
	while (fgets(trash.area, trash.size, file) != NULL) {
		line++;
		c = trash.area;

		/* ignore lines beginning with a dash */
		if (*c == '#')
			continue;

		/* strip leading spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;


		arg = c;
		while (*c && *c != '\n' && *c != '\r')
			c++;
		*c = 0;

		/* empty lines are ignored too */
		if (c == arg)
			continue;

		if (!pat_ref_append(ref, arg, NULL, line)) {
			memprintf(err, "out of memory when loading patterns from file <%s>", ref->reference);
			goto out_close;
		}
	}

	if (ferror(file)) {
		memprintf(err, "error encountered while reading  <%s> : %s",
				ref->reference, strerror(errno));
		goto out_close;
	}
	ret = 1; /* success */

 out_close:
	fclose(file);
	return ret;
}

int pattern_read_from_file(struct pattern_head *head, unsigned int refflags,
                           const char *filename, int patflags, int load_smp,
                           char **err, const char *file, int line)
{
	struct pat_ref *ref;
	struct pattern_expr *expr;
	struct pat_ref_elt *elt;
	int reuse = 0;

	/* Lookup for the existing reference. */
	ref = pat_ref_lookup(filename);

	/* If the reference doesn't exists, create it and load associated file. */
	if (!ref) {
		chunk_printf(&trash,
		             "pattern loaded from file '%s' used by %s at file '%s' line %d",
		             filename, refflags & PAT_REF_MAP ? "map" : "acl", file, line);

		ref = pat_ref_new(filename, trash.area, refflags);
		if (!ref) {
			memprintf(err, "out of memory");
			return 0;
		}

		if (ref->flags & PAT_REF_FILE) {
			if (load_smp) {
				ref->flags |= PAT_REF_SMP;
				if (!pat_ref_read_from_file_smp(ref, err))
					return 0;
			}
			else {
				if (!pat_ref_read_from_file(ref, err))
					return 0;
			}
		}
	}
	else {
		/* The reference already exists, check the map compatibility. */

		/* If the load require samples and the flag PAT_REF_SMP is not set,
		 * the reference doesn't contain sample, and cannot be used.
		 */
		if (load_smp) {
			if (!(ref->flags & PAT_REF_SMP)) {
				memprintf(err, "The file \"%s\" is already used as one column file "
				               "and cannot be used by as two column file.",
				               filename);
				return 0;
			}
		}
		else {
			/* The load doesn't require samples. If the flag PAT_REF_SMP is
			 * set, the reference contains a sample, and cannot be used.
			 */
			if (ref->flags & PAT_REF_SMP) {
				memprintf(err, "The file \"%s\" is already used as two column file "
				               "and cannot be used by as one column file.",
				               filename);
				return 0;
			}
		}

		/* Extends display */
		chunk_printf(&trash, "%s", ref->display);
		chunk_appendf(&trash, ", by %s at file '%s' line %d",
		              refflags & PAT_REF_MAP ? "map" : "acl", file, line);
		free(ref->display);
		ref->display = strdup(trash.area);
		if (!ref->display) {
			memprintf(err, "out of memory");
			return 0;
		}

		/* Merge flags. */
		ref->flags |= refflags;
	}

	/* Now, we can loading patterns from the reference. */

	/* Lookup for existing reference in the head. If the reference
	 * doesn't exists, create it.
	 */
	expr = pattern_lookup_expr(head, ref);
	if (!expr || (expr->mflags != patflags)) {
		expr = pattern_new_expr(head, ref, patflags, err, &reuse);
		if (!expr)
			return 0;
	}

	/* The returned expression may be not empty, because the function
	 * "pattern_new_expr" lookup for similar pattern list and can
	 * reuse a already filled pattern list. In this case, we can not
	 * reload the patterns.
	 */
	if (reuse)
		return 1;

	/* Load reference content in the pattern expression.
	 * We need to load elements in the same order they were seen in the
	 * file. Indeed, some list-based matching types may rely on it as the
	 * list is positional, and for tree-based matching, even if the tree is
	 * content-based in case of duplicated keys we only want the first key
	 * in the file to be considered.
	 */
	list_for_each_entry(elt, &ref->head, list) {
		if (!pat_ref_push(elt, expr, patflags, err)) {
			if (elt->line > 0)
				memprintf(err, "%s at line %d of file '%s'",
				          *err, elt->line, filename);
			return 0;
		}
	}

	return 1;
}

/* This function executes a pattern match on a sample. It applies pattern <expr>
 * to sample <smp>. The function returns NULL if the sample don't match. It returns
 * non-null if the sample match. If <fill> is true and the sample match, the
 * function returns the matched pattern. In many cases, this pattern can be a
 * static buffer.
 */
struct pattern *pattern_exec_match(struct pattern_head *head, struct sample *smp, int fill)
{
	struct pattern_expr_list *list;
	struct pattern *pat;

	if (!head->match) {
		if (fill) {
			static_pattern.data = NULL;
			static_pattern.ref = NULL;
			static_pattern.sflags = 0;
			static_pattern.type = SMP_T_SINT;
			static_pattern.val.i = 1;
		}
		return &static_pattern;
	}

	/* convert input to string */
	if (!sample_convert(smp, head->expect_type))
		return NULL;

	list_for_each_entry(list, &head->head, list) {
		HA_RWLOCK_RDLOCK(PATEXP_LOCK, &list->expr->lock);
		pat = head->match(smp, list->expr, fill);
		if (pat) {
			/* We duplicate the pattern cause it could be modified
			   by another thread */
			if (pat != &static_pattern) {
				memcpy(&static_pattern, pat, sizeof(struct pattern));
				pat = &static_pattern;
			}

			/* We also duplicate the sample data for
			   same reason */
			if (pat->data && (pat->data != &static_sample_data)) {
				switch(pat->data->type) {
					case SMP_T_STR:
						static_sample_data.type = SMP_T_STR;
						static_sample_data.u.str = *get_trash_chunk();
						static_sample_data.u.str.data = pat->data->u.str.data;
						if (static_sample_data.u.str.data >= static_sample_data.u.str.size)
							static_sample_data.u.str.data = static_sample_data.u.str.size - 1;
						memcpy(static_sample_data.u.str.area,
						       pat->data->u.str.area, static_sample_data.u.str.data);
						static_sample_data.u.str.area[static_sample_data.u.str.data] = 0;
						pat->data = &static_sample_data;
						break;

					case SMP_T_IPV4:
					case SMP_T_IPV6:
					case SMP_T_SINT:
						memcpy(&static_sample_data, pat->data, sizeof(struct sample_data));
						pat->data = &static_sample_data;
						break;
					default:
						/* unimplemented pattern type */
						pat->data = NULL;
						break;
				}
			}
			HA_RWLOCK_RDUNLOCK(PATEXP_LOCK, &list->expr->lock);
			return pat;
		}
		HA_RWLOCK_RDUNLOCK(PATEXP_LOCK, &list->expr->lock);
	}
	return NULL;
}

/* This function prunes the pattern expressions starting at pattern_head <head>. */
void pattern_prune(struct pattern_head *head)
{
	struct pattern_expr_list *list, *safe;

	list_for_each_entry_safe(list, safe, &head->head, list) {
		LIST_DELETE(&list->list);
		if (HA_ATOMIC_SUB_FETCH(&list->expr->refcount, 1) == 0) {
			LIST_DELETE(&list->expr->list);
			HA_RWLOCK_WRLOCK(PATEXP_LOCK, &list->expr->lock);
			head->prune(list->expr);
			HA_RWLOCK_WRUNLOCK(PATEXP_LOCK, &list->expr->lock);
			free(list->expr);
		}
		free(list);
	}
}

/* This function compares two pat_ref** on their unique_id, and returns -1/0/1
 * depending on their order (suitable for sorting).
 */
static int cmp_pat_ref(const void *_a, const void *_b)
{
	struct pat_ref * const *a = _a;
	struct pat_ref * const *b = _b;

	if ((*a)->unique_id < (*b)->unique_id)
		return -1;
	else if ((*a)->unique_id > (*b)->unique_id)
		return 1;
	return 0;
}

/* This function finalizes the configuration parsing. It sets all the
 * automatic ids.
 */
int pattern_finalize_config(void)
{
	size_t len = 0;
	size_t unassigned_pos = 0;
	int next_unique_id = 0;
	size_t i, j;
	struct pat_ref *ref, **arr;
	struct list pr = LIST_HEAD_INIT(pr);

	pat_lru_seed = ha_random();

	/* Count pat_refs with user defined unique_id and totalt count */
	list_for_each_entry(ref, &pattern_reference, list) {
		len++;
		if (ref->unique_id != -1)
			unassigned_pos++;
	}

	if (len == 0) {
		return 0;
	}

	arr = calloc(len, sizeof(*arr));
	if (arr == NULL) {
		ha_alert("Out of memory error.\n");
		return ERR_ALERT | ERR_FATAL;
	}

	i = 0;
	j = unassigned_pos;
	list_for_each_entry(ref, &pattern_reference, list) {
		if (ref->unique_id != -1)
			arr[i++] = ref;
		else
			arr[j++] = ref;
	}

	/* Sort first segment of array with user-defined unique ids for
	 * fast lookup when generating unique ids
	 */
	qsort(arr, unassigned_pos, sizeof(*arr), cmp_pat_ref);

	/* Assign unique ids to the rest of the elements */
	for (i = unassigned_pos; i < len; i++) {
		do {
			arr[i]->unique_id = next_unique_id++;
		} while (bsearch(&arr[i], arr, unassigned_pos, sizeof(*arr), cmp_pat_ref));
	}

	/* Sort complete array */
	qsort(arr, len, sizeof(*arr), cmp_pat_ref);

	/* Convert back to linked list */
	for (i = 0; i < len; i++)
		LIST_APPEND(&pr, &arr[i]->list);

	/* swap root */
	LIST_INSERT(&pr, &pattern_reference);
	LIST_DELETE(&pr);

	free(arr);
	return 0;
}

static int pattern_per_thread_lru_alloc()
{
	if (!global.tune.pattern_cache)
		return 1;
	pat_lru_tree = lru64_new(global.tune.pattern_cache);
	return !!pat_lru_tree;
}

static void pattern_per_thread_lru_free()
{
	lru64_destroy(pat_lru_tree);
}

REGISTER_PER_THREAD_ALLOC(pattern_per_thread_lru_alloc);
REGISTER_PER_THREAD_FREE(pattern_per_thread_lru_free);
