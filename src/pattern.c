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

#include <common/config.h>
#include <common/standard.h>

#include <types/global.h>
#include <types/pattern.h>

#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/sample.h>

#include <ebsttree.h>

char *pat_match_names[PAT_MATCH_NUM] = {
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
};

int (*pat_parse_fcts[PAT_MATCH_NUM])(const char *, struct pattern *, int, char **) = {
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
};

int (*pat_index_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pattern *, char **) = {
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
};

void (*pat_delete_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pat_ref_elt *) = {
	[PAT_MATCH_FOUND] = pat_del_list_val,
	[PAT_MATCH_BOOL]  = pat_del_list_val,
	[PAT_MATCH_INT]   = pat_del_list_val,
	[PAT_MATCH_IP]    = pat_del_tree_ip,
	[PAT_MATCH_BIN]   = pat_del_list_ptr,
	[PAT_MATCH_LEN]   = pat_del_list_val,
	[PAT_MATCH_STR]   = pat_del_tree_str,
	[PAT_MATCH_BEG]   = pat_del_tree_str,
	[PAT_MATCH_SUB]   = pat_del_list_ptr,
	[PAT_MATCH_DIR]   = pat_del_list_ptr,
	[PAT_MATCH_DOM]   = pat_del_list_ptr,
	[PAT_MATCH_END]   = pat_del_list_ptr,
	[PAT_MATCH_REG]   = pat_del_list_reg,
};

void (*pat_prune_fcts[PAT_MATCH_NUM])(struct pattern_expr *) = {
	[PAT_MATCH_FOUND] = pat_prune_val,
	[PAT_MATCH_BOOL]  = pat_prune_val,
	[PAT_MATCH_INT]   = pat_prune_val,
	[PAT_MATCH_IP]    = pat_prune_val,
	[PAT_MATCH_BIN]   = pat_prune_ptr,
	[PAT_MATCH_LEN]   = pat_prune_val,
	[PAT_MATCH_STR]   = pat_prune_ptr,
	[PAT_MATCH_BEG]   = pat_prune_ptr,
	[PAT_MATCH_SUB]   = pat_prune_ptr,
	[PAT_MATCH_DIR]   = pat_prune_ptr,
	[PAT_MATCH_DOM]   = pat_prune_ptr,
	[PAT_MATCH_END]   = pat_prune_ptr,
	[PAT_MATCH_REG]   = pat_prune_reg,
};

struct pattern *(*pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern_expr *, int) = {
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
};

/* Just used for checking configuration compatibility */
int pat_match_types[PAT_MATCH_NUM] = {
	[PAT_MATCH_FOUND] = SMP_T_UINT,
	[PAT_MATCH_BOOL]  = SMP_T_UINT,
	[PAT_MATCH_INT]   = SMP_T_UINT,
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
};

/* this struct is used to return information */
static struct pattern static_pattern;

/* This is the root of the list of all pattern_ref avalaibles. */
struct list pattern_reference = LIST_HEAD_INIT(pattern_reference);

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
 * The following functions are used for parsing pattern matching
 * input value. The <text> contain the string to be parsed. <pattern>
 * must be a preallocated pattern. The pat_parse_* functions fill this
 * structure with the parsed value. <usage> can be PAT_U_COMPILE or
 * PAT_U_LOOKUP. If the value PAT_U_COMPILE is used memory is allocated
 * for filling the pattern. If the value PAT_U_LOOKUP is set, the parser
 * use "trash" or return pointers to the input strings. In both cases,
 * the caller must use the value PAT_U_LOOKUP with caution. <err> is
 * filled with an error message built with memprintf() function.
 *
 * In succes case, the pat_parse_* function return 1. If the function
 * fail, it returns 0 and <err> is filled.
 *
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
	struct chunk *trash;

	pattern->type = SMP_T_BIN;
	trash = get_trash_chunk();
	pattern->len = trash->size;
	pattern->ptr.str = trash->str;
	return !!parse_binary(text, &pattern->ptr.str, &pattern->len, err);
}

/* Parse a regex. It is allocated. */
int pat_parse_reg(const char *text, struct pattern *pattern, int mflags, char **err)
{
	struct chunk *trash;

	trash = get_trash_chunk();
	if (trash->size < sizeof(*pattern->ptr.reg)) {
		memprintf(err, "no space avalaible in the buffer. expect %d, provides %d",
		          (int)sizeof(*pattern->ptr.reg), trash->size);
		return 0;
	}

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

	pattern->type = SMP_T_UINT;

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

	pattern->type = SMP_T_UINT;

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
 * This fucntion just take a sample <smp> and check if this sample match
 * with the pattern <pattern>. This fucntion return just PAT_MATCH or
 * PAT_NOMATCH.
 *
 */

/* always return false */
struct pattern *pat_match_nothing(struct sample *smp, struct pattern_expr *expr, int fill)
{
	if (smp->data.uint) {
		if (fill) {
			static_pattern.smp = NULL;
			static_pattern.ref = NULL;
			static_pattern.type = 0;
			static_pattern.ptr.str = NULL;
		}
		return &static_pattern;
	}
	else
		return NULL;
}


/* NB: For two strings to be identical, it is required that their lengths match */
struct pattern *pat_match_str(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct ebmb_node *node;
	char prev;
	struct pattern_tree *elt;
	struct pattern_list *lst;
	struct pattern *pattern;

	/* Lookup a string in the expression's pattern tree. */
	if (!eb_is_empty(&expr->pattern_tree)) {
		/* we may have to force a trailing zero on the test pattern */
		prev = smp->data.str.str[smp->data.str.len];
		if (prev)
			smp->data.str.str[smp->data.str.len] = '\0';
		node = ebst_lookup(&expr->pattern_tree, smp->data.str.str);
		if (prev)
			smp->data.str.str[smp->data.str.len] = prev;

		if (node) {
			if (fill) {
				elt = ebmb_entry(node, struct pattern_tree, node);
				static_pattern.smp = elt->smp;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_STR;
				static_pattern.ptr.str = (char *)elt->node.key;
			}
			return &static_pattern;
		}
	}

	/* look in the list */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->len != smp->data.str.len)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0))
			return pattern;
	}

	return NULL;
}

/* NB: For two binaries buf to be identical, it is required that their lengths match */
struct pattern *pat_match_bin(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	/* Look in the list. */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->len != smp->data.str.len)
			continue;

		if (memcmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0)
			return pattern;
	}

	return NULL;
}

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
struct pattern *pat_match_reg(struct sample *smp, struct pattern_expr *expr, int fill)
{
	struct pattern_list *lst;
	struct pattern *pattern;

	/* look in the list */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (regex_exec2(pattern->ptr.reg, smp->data.str.str, smp->data.str.len))
			return pattern;
	}
	return NULL;
}

/* Checks that the pattern matches the beginning of the tested string. */
struct pattern *pat_match_beg(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct ebmb_node *node;
	char prev;
	struct pattern_tree *elt;
	struct pattern_list *lst;
	struct pattern *pattern;

	/* Lookup a string in the expression's pattern tree. */
	if (!eb_is_empty(&expr->pattern_tree)) {
		/* we may have to force a trailing zero on the test pattern */
		prev = smp->data.str.str[smp->data.str.len];
		if (prev)
			smp->data.str.str[smp->data.str.len] = '\0';
		node = ebmb_lookup_longest(&expr->pattern_tree, smp->data.str.str);
		if (prev)
			smp->data.str.str[smp->data.str.len] = prev;

		if (node) {
			if (fill) {
				elt = ebmb_entry(node, struct pattern_tree, node);
				static_pattern.smp = elt->smp;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_STR;
				static_pattern.ptr.str = (char *)elt->node.key;
			}
			return &static_pattern;
		}
	}

	/* look in the list */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->len > smp->data.str.len)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0))
			continue;

		return pattern;
	}
	return NULL;
}

/* Checks that the pattern matches the end of the tested string. */
struct pattern *pat_match_end(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->len > smp->data.str.len)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0))
			continue;

		return pattern;
	}
	return  NULL;
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

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		if (pattern->len > smp->data.str.len)
			continue;

		end = smp->data.str.str + smp->data.str.len - pattern->len;
		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if (icase) {
			for (c = smp->data.str.str; c <= end; c++) {
				if (tolower(*c) != tolower(*pattern->ptr.str))
					continue;
				if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0)
					return pattern;
			}
		} else {
			for (c = smp->data.str.str; c <= end; c++) {
				if (*c != *pattern->ptr.str)
					continue;
				if (strncmp(pattern->ptr.str, c, pattern->len) == 0)
					return pattern;
			}
		}
	}
	return NULL;
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

	if (pl > smp->data.str.len)
		return PAT_NOMATCH;

	may_match = 1;
	icase = mflags & PAT_MF_IGNORE_CASE;
	end = smp->data.str.str + smp->data.str.len - pl;
	for (c = smp->data.str.str; c <= end; c++) {
		if (is_delimiter(*c, delimiters)) {
			may_match = 1;
			continue;
		}

		if (!may_match)
			continue;

		if (icase) {
			if ((tolower(*c) == tolower(*ps)) &&
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
		if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.uint) &&
		    (!pattern->val.range.max_set || smp->data.uint <= pattern->val.range.max))
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
		if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.str.len) &&
		    (!pattern->val.range.max_set || smp->data.str.len <= pattern->val.range.max))
			return pattern;
	}
	return NULL;
}

struct pattern *pat_match_ip(struct sample *smp, struct pattern_expr *expr, int fill)
{
	unsigned int v4; /* in network byte order */
	struct in6_addr tmp6;
	struct in_addr *s;
	struct ebmb_node *node;
	struct pattern_tree *elt;
	struct pattern_list *lst;
	struct pattern *pattern;

	/* The input sample is IPv4. Try to match in the trees. */
	if (smp->type == SMP_T_IPV4) {
		/* Lookup an IPv4 address in the expression's pattern tree using
		 * the longest match method.
		 */
		s = &smp->data.ipv4;
		node = ebmb_lookup_longest(&expr->pattern_tree, &s->s_addr);
		if (node) {
			if (fill) {
				elt = ebmb_entry(node, struct pattern_tree, node);
				static_pattern.smp = elt->smp;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_IPV4;
				memcpy(&static_pattern.val.ipv4.addr.s_addr, elt->node.key, 4);
				if (!cidr2dotted(elt->node.node.pfx, &static_pattern.val.ipv4.mask))
					return NULL;
			}
			return &static_pattern;
		}

		/* The IPv4 sample dont match the IPv4 tree. Convert the IPv4
		 * sample address to IPv6 with the mapping method using the ::ffff:
		 * prefix, and try to lookup in the IPv6 tree.
		 */
		memset(&tmp6, 0, 10);
		*(uint16_t*)&tmp6.s6_addr[10] = htons(0xffff);
		*(uint32_t*)&tmp6.s6_addr[12] = smp->data.ipv4.s_addr;
		node = ebmb_lookup_longest(&expr->pattern_tree_2, &tmp6);
		if (node) {
			if (fill) {
				elt = ebmb_entry(node, struct pattern_tree, node);
				static_pattern.smp = elt->smp;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_IPV6;
				memcpy(&static_pattern.val.ipv6.addr, elt->node.key, 16);
				static_pattern.val.ipv6.mask = elt->node.node.pfx;
			}
			return &static_pattern;
		}
	}

	/* The input sample is IPv6. Try to match in the trees. */
	if (smp->type == SMP_T_IPV6) {
		/* Lookup an IPv6 address in the expression's pattern tree using
		 * the longest match method.
		 */
		node = ebmb_lookup_longest(&expr->pattern_tree_2, &smp->data.ipv6);
		if (node) {
			if (fill) {
				elt = ebmb_entry(node, struct pattern_tree, node);
				static_pattern.smp = elt->smp;
				static_pattern.ref = elt->ref;
				static_pattern.sflags = PAT_SF_TREE;
				static_pattern.type = SMP_T_IPV6;
				memcpy(&static_pattern.val.ipv6.addr, elt->node.key, 16);
				static_pattern.val.ipv6.mask = elt->node.node.pfx;
			}
			return &static_pattern;
		}

		/* Try to convert 6 to 4 when the start of the ipv6 address match the
		 * following forms :
		 *   - ::ffff:ip:v4 (ipv4 mapped)
		 *   - ::0000:ip:v4 (old ipv4 mapped)
		 *   - 2002:ip:v4:: (6to4)
		 */
		if ((*(uint32_t*)&smp->data.ipv6.s6_addr[0] == 0 &&
		     *(uint32_t*)&smp->data.ipv6.s6_addr[4]  == 0 &&
		     (*(uint32_t*)&smp->data.ipv6.s6_addr[8] == 0 ||
		      *(uint32_t*)&smp->data.ipv6.s6_addr[8] == htonl(0xFFFF))) ||
		    *(uint16_t*)&smp->data.ipv6.s6_addr[0] == htons(0x2002)) {
			if (*(uint32_t*)&smp->data.ipv6.s6_addr[0] == 0)
				v4 = *(uint32_t*)&smp->data.ipv6.s6_addr[12];
			else
				v4 = htonl((ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[2]) << 16) +
				            ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[4]));

			/* Lookup an IPv4 address in the expression's pattern tree using the longest
			 * match method.
			 */
			node = ebmb_lookup_longest(&expr->pattern_tree, &v4);
			if (node) {
				if (fill) {
					elt = ebmb_entry(node, struct pattern_tree, node);
					static_pattern.smp = elt->smp;
					static_pattern.ref = elt->ref;
					static_pattern.sflags = PAT_SF_TREE;
					static_pattern.type = SMP_T_IPV4;
					memcpy(&static_pattern.val.ipv4.addr.s_addr, elt->node.key, 4);
					if (!cidr2dotted(elt->node.node.pfx, &static_pattern.val.ipv4.mask))
						return NULL;
				}
				return &static_pattern;
			}
		}
	}

	/* Lookup in the list. the list contain only IPv4 patterns */
	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		/* The input sample is IPv4, use it as is. */
		if (smp->type == SMP_T_IPV4) {
			v4 = smp->data.ipv4.s_addr;
		}
		else if (smp->type == SMP_T_IPV6) {
			/* v4 match on a V6 sample. We want to check at least for
			 * the following forms :
			 *   - ::ffff:ip:v4 (ipv4 mapped)
			 *   - ::0000:ip:v4 (old ipv4 mapped)
			 *   - 2002:ip:v4:: (6to4)
			 */
			if (*(uint32_t*)&smp->data.ipv6.s6_addr[0] == 0 &&
			    *(uint32_t*)&smp->data.ipv6.s6_addr[4]  == 0 &&
			    (*(uint32_t*)&smp->data.ipv6.s6_addr[8] == 0 ||
			     *(uint32_t*)&smp->data.ipv6.s6_addr[8] == htonl(0xFFFF))) {
				v4 = *(uint32_t*)&smp->data.ipv6.s6_addr[12];
			}
			else if (*(uint16_t*)&smp->data.ipv6.s6_addr[0] == htons(0x2002)) {
				v4 = htonl((ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[2]) << 16) +
				            ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[4]));
			}
			else
				continue;
		}

		/* Check if the input sample match the current pattern. */
		if (((v4 ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
			return pattern;
	}
	return NULL;
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
		free(elt->smp);
		free(elt);
		node = next;
	}
}

void pat_prune_val(struct pattern_expr *expr)
{
	struct pattern_list *pat, *tmp;

	list_for_each_entry_safe(pat, tmp, &expr->patterns, list) {
		free(pat->pat.smp);
		free(pat);
	}

	free_pattern_tree(&expr->pattern_tree);
	free_pattern_tree(&expr->pattern_tree_2);
	LIST_INIT(&expr->patterns);
}

void pat_prune_ptr(struct pattern_expr *expr)
{
	struct pattern_list *pat, *tmp;

	list_for_each_entry_safe(pat, tmp, &expr->patterns, list) {
		free(pat->pat.ptr.ptr);
		free(pat->pat.smp);
		free(pat);
	}

	free_pattern_tree(&expr->pattern_tree);
	free_pattern_tree(&expr->pattern_tree_2);
	LIST_INIT(&expr->patterns);
}

void pat_prune_reg(struct pattern_expr *expr)
{
	struct pattern_list *pat, *tmp;

	list_for_each_entry_safe(pat, tmp, &expr->patterns, list) {
		regex_free(pat->pat.ptr.ptr);
		free(pat->pat.smp);
		free(pat);
	}

	free_pattern_tree(&expr->pattern_tree);
	free_pattern_tree(&expr->pattern_tree_2);
	LIST_INIT(&expr->patterns);
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
	LIST_ADDQ(&expr->patterns, &patl->list);

	/* that's ok */
	return 1;
}

int pat_idx_list_ptr(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	struct pattern_list *patl;

	/* allocate pattern */
	patl = calloc(1, sizeof(*patl));
	if (!patl)
		return 0;

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
	LIST_ADDQ(&expr->patterns, &patl->list);

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
	LIST_ADDQ(&expr->patterns, &patl->list);

	/* that's ok */
	return 1;
}

int pat_idx_list_reg(struct pattern_expr *expr, struct pattern *pat, char **err)
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

	/* allocate regex */
	patl->pat.ptr.reg = calloc(1, sizeof(*patl->pat.ptr.reg));
	if (!patl->pat.ptr.reg) {
		free(patl);
		memprintf(err, "out of memory while indexing pattern");
		return 0;
	}

	/* compile regex */
	if (!regex_comp(pat->ptr.str, patl->pat.ptr.reg, !(expr->mflags & PAT_MF_IGNORE_CASE), 0, err)) {
		free(patl->pat.ptr.reg);
		free(patl);
		return 0;
	}

	/* chain pattern in the expression */
	LIST_ADDQ(&expr->patterns, &patl->list);

	/* that's ok */
	return 1;
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
			node->smp = pat->smp;
			node->ref = pat->ref;

			/* FIXME: insert <addr>/<mask> into the tree here */
			memcpy(node->node.key, &pat->val.ipv4.addr, 4); /* network byte order */
			node->node.node.pfx = mask;

			/* Insert the entry. */
			ebmb_insert_prefix(&expr->pattern_tree, &node->node, 4);

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
		node->smp = pat->smp;
		node->ref = pat->ref;

		/* FIXME: insert <addr>/<mask> into the tree here */
		memcpy(node->node.key, &pat->val.ipv6.addr, 16); /* network byte order */
		node->node.node.pfx = pat->val.ipv6.mask;

		/* Insert the entry. */
		ebmb_insert_prefix(&expr->pattern_tree_2, &node->node, 16);

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
	node->smp = pat->smp;
	node->ref = pat->ref;

	/* copy the string */
	memcpy(node->node.key, pat->ptr.str, len);

	/* index the new node */
	ebst_insert(&expr->pattern_tree, &node->node);

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
	node->smp = pat->smp;
	node->ref = pat->ref;

	/* copy the string and the trailing zero */
	memcpy(node->node.key, pat->ptr.str, len + 1);
	node->node.node.pfx = len * 8;

	/* index the new node */
	ebmb_insert_prefix(&expr->pattern_tree, &node->node, len);

	/* that's ok */
	return 1;
}

void pat_del_list_val(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct pattern_list *pat;
	struct pattern_list *safe;

	list_for_each_entry_safe(pat, safe, &expr->patterns, list) {
		/* Check equality. */
		if (pat->pat.ref != ref)
			continue;

		/* Delete and free entry. */
		LIST_DEL(&pat->list);
		free(pat->pat.smp);
		free(pat);
	}
}

void pat_del_tree_ip(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct ebmb_node *node, *next_node;
	struct pattern_tree *elt;

	/* browse each node of the tree for IPv4 addresses. */
	for (node = ebmb_first(&expr->pattern_tree), next_node = node ? ebmb_next(node) : NULL;
	     node;
	     node = next_node, next_node = node ? ebmb_next(node) : NULL) {
		/* Extract container of the tree node. */
		elt = container_of(node, struct pattern_tree, node);

		/* Check equality. */
		if (elt->ref != ref)
			continue;

		/* Delete and free entry. */
		ebmb_delete(node);
		free(elt->smp);
		free(elt);
	}

	/* Browse each node of the list for IPv4 addresses. */
	pat_del_list_val(expr, ref);

	/* browse each node of the tree for IPv6 addresses. */
	for (node = ebmb_first(&expr->pattern_tree_2), next_node = node ? ebmb_next(node) : NULL;
	     node;
	     node = next_node, next_node = node ? ebmb_next(node) : NULL) {
		/* Extract container of the tree node. */
		elt = container_of(node, struct pattern_tree, node);

		/* Check equality. */
		if (elt->ref != ref)
			continue;

		/* Delete and free entry. */
		ebmb_delete(node);
		free(elt->smp);
		free(elt);
	}
}

void pat_del_list_ptr(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct pattern_list *pat;
	struct pattern_list *safe;

	list_for_each_entry_safe(pat, safe, &expr->patterns, list) {
		/* Check equality. */
		if (pat->pat.ref != ref)
			continue;

		/* Delete and free entry. */
		LIST_DEL(&pat->list);
		free(pat->pat.ptr.ptr);
		free(pat->pat.smp);
		free(pat);
	}
}

void pat_del_tree_str(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct ebmb_node *node, *next_node;
	struct pattern_tree *elt;

	/* browse each node of the tree. */
	for (node = ebmb_first(&expr->pattern_tree), next_node = node ? ebmb_next(node) : NULL;
	     node;
	     node = next_node, next_node = node ? ebmb_next(node) : NULL) {
		/* Extract container of the tree node. */
		elt = container_of(node, struct pattern_tree, node);

		/* Check equality. */
		if (elt->ref != ref)
			continue;

		/* Delete and free entry. */
		ebmb_delete(node);
		free(elt->smp);
		free(elt);
	}
}

void pat_del_list_reg(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct pattern_list *pat;
	struct pattern_list *safe;

	list_for_each_entry_safe(pat, safe, &expr->patterns, list) {
		/* Check equality. */
		if (pat->pat.ref != ref)
			continue;

		/* Delete and free entry. */
		LIST_DEL(&pat->list);
		regex_free(pat->pat.ptr.ptr);
		free(pat->pat.smp);
		free(pat);
	}
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

/* This function lookup for reference. If the reference is found, they return
 * pointer to the struct pat_ref, else return NULL.
 */
struct pat_ref *pat_ref_lookup(const char *reference)
{
	struct pat_ref *ref;

	list_for_each_entry(ref, &pattern_reference, list)
		if (ref->reference && strcmp(reference, ref->reference) == 0)
			return ref;
	return NULL;
}

/* This function lookup for unique id. If the reference is found, they return
 * pointer to the struct pat_ref, else return NULL.
 */
struct pat_ref *pat_ref_lookupid(int unique_id)
{
	struct pat_ref *ref;

	list_for_each_entry(ref, &pattern_reference, list)
		if (ref->unique_id == unique_id)
			return ref;
	return NULL;
}

/* This function remove all pattern matching the pointer <refelt> from
 * the the reference and from each expr member of the reference. This
 * function returns 1 if the deletion is done and return 0 is the entry
 * is not found.
 */
int pat_ref_delete_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt)
{
	struct pattern_expr *expr;
	struct pat_ref_elt *elt, *safe;

	/* delete pattern from reference */
	list_for_each_entry_safe(elt, safe, &ref->head, list) {
		if (elt == refelt) {
			LIST_DEL(&elt->list);
			free(elt->sample);
			free(elt->pattern);
			free(elt);

			list_for_each_entry(expr, &ref->pat, list)
				pattern_delete(expr, elt);

			return 1;
		}
	}
	return 0;
}

/* This function remove all pattern match <key> from the the reference
 * and from each expr member of the reference. This fucntion returns 1
 * if the deletion is done and return 0 is the entry is not found.
 */
int pat_ref_delete(struct pat_ref *ref, const char *key)
{
	struct pattern_expr *expr;
	struct pat_ref_elt *elt, *safe;
	int found = 0;

	/* delete pattern from reference */
	list_for_each_entry_safe(elt, safe, &ref->head, list) {
		if (strcmp(key, elt->pattern) == 0) {
			list_for_each_entry(expr, &ref->pat, list)
				pattern_delete(expr, elt);

			LIST_DEL(&elt->list);
			free(elt->sample);
			free(elt->pattern);
			free(elt);

			found = 1;
		}
	}

	if (!found)
		return 0;
	return 1;
}

/*
 * find and return an element <elt> matching <key> in a reference <ref>
 * return NULL if not found
 */
struct pat_ref_elt *pat_ref_find_elt(struct pat_ref *ref, const char *key)
{
	struct pat_ref_elt *elt;

	list_for_each_entry(elt, &ref->head, list) {
		if (strcmp(key, elt->pattern) == 0)
			return elt;
	}

	return NULL;
}


  /* This function modify the sample of the first pattern that match the <key>. */
static inline int pat_ref_set_elt(struct pat_ref *ref, struct pat_ref_elt *elt,
                                  const char *value, char **err)
{
	struct pattern_expr *expr;
	struct sample_storage **smp;
	char *sample;
	struct sample_storage test;

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
	free(elt->sample);
	elt->sample = sample;

	/* Load sample in each reference. All the conversion are tested
	 * below, normally these calls dosn't fail.
	 */
	list_for_each_entry(expr, &ref->pat, list) {
		if (!expr->pat_head->parse_smp)
			continue;

		smp = pattern_find_smp(expr, elt);
		if (smp && *smp && !expr->pat_head->parse_smp(sample, *smp))
			*smp = NULL;
	}

	return 1;
}

/* This function modify the sample of the first pattern that match the <key>. */
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

/* This function modify the sample of the first pattern that match the <key>. */
int pat_ref_set(struct pat_ref *ref, const char *key, const char *value, char **err)
{
	struct pat_ref_elt *elt;
	int found = 0;
	char *_merr;
	char **merr;

	if (err) {
		merr = &_merr;
		*merr = NULL;
	}
	else
		merr = NULL;

	/* Look for pattern in the reference. */
	list_for_each_entry(elt, &ref->head, list) {
		if (strcmp(key, elt->pattern) == 0) {
			if (!pat_ref_set_elt(ref, elt, value, merr)) {
				if (!found)
					*err = *merr;
				else {
					memprintf(err, "%s, %s", *err, *merr);
					free(*merr);
					*merr = NULL;
				}
			}
			found = 1;
		}
	}

	if (!found) {
		memprintf(err, "entry not found");
		return 0;
	}
	return 1;
}

/* This function create new reference. <ref> is the reference name.
 * <flags> are PAT_REF_*. /!\ The reference is not checked, and must
 * be unique. The user must check the reference with "pat_ref_lookup()"
 * before calling this function. If the fucntion fail, it return NULL,
 * else return new struct pat_ref.
 */
struct pat_ref *pat_ref_new(const char *reference, const char *display, unsigned int flags)
{
	struct pat_ref *ref;

	ref = malloc(sizeof(*ref));
	if (!ref)
		return NULL;

	if (display) {
		ref->display = strdup(display);
		if (!ref->display) {
			free(ref);
			return NULL;
		}
	}
	else
		ref->display = NULL;

	ref->reference = strdup(reference);
	if (!ref->reference) {
		free(ref->display);
		free(ref);
		return NULL;
	}

	ref->flags = flags;
	ref->unique_id = -1;

	LIST_INIT(&ref->head);
	LIST_INIT(&ref->pat);

	LIST_ADDQ(&pattern_reference, &ref->list);

	return ref;
}

/* This function create new reference. <unique_id> is the unique id. If
 * the value of <unique_id> is -1, the unique id is calculated later.
 * <flags> are PAT_REF_*. /!\ The reference is not checked, and must
 * be unique. The user must check the reference with "pat_ref_lookup()"
 * or pat_ref_lookupid before calling this function. If the function
 * fail, it return NULL, else return new struct pat_ref.
 */
struct pat_ref *pat_ref_newid(int unique_id, const char *display, unsigned int flags)
{
	struct pat_ref *ref;

	ref = malloc(sizeof(*ref));
	if (!ref)
		return NULL;

	if (display) {
		ref->display = strdup(display);
		if (!ref->display) {
			free(ref);
			return NULL;
		}
	}
	else
		ref->display = NULL;

	ref->reference = NULL;
	ref->flags = flags;
	ref->unique_id = unique_id;
	LIST_INIT(&ref->head);
	LIST_INIT(&ref->pat);

	LIST_ADDQ(&pattern_reference, &ref->list);

	return ref;
}

/* This function adds entry to <ref>. It can failed with memory error.
 * If the function fails, it returns 0.
 */
int pat_ref_append(struct pat_ref *ref, char *pattern, char *sample, int line)
{
	struct pat_ref_elt *elt;

	elt = malloc(sizeof(*elt));
	if (!elt)
		return 0;

	elt->line = line;

	elt->pattern = strdup(pattern);
	if (!elt->pattern) {
		free(elt);
		return 0;
	}

	if (sample) {
		elt->sample = strdup(sample);
		if (!elt->sample) {
			free(elt->pattern);
			free(elt);
			return 0;
		}
	}
	else
		elt->sample = NULL;

	LIST_ADDQ(&ref->head, &elt->list);

	return 1;
}

/* This function create sample found in <elt>, parse the pattern also
 * found in <elt> and insert it in <expr>. The function copy <patflags>
 * in <expr>. If the function fails, it returns0 and <err> is filled.
 * In succes case, the function returns 1.
 */
static inline
int pat_ref_push(struct pat_ref_elt *elt, struct pattern_expr *expr,
                 int patflags, char **err)
{
	struct sample_storage *smp;
	struct pattern pattern;

	/* Create sample */
	if (elt->sample && expr->pat_head->parse_smp) {
		/* New sample. */
		smp = malloc(sizeof(*smp));
		if (!smp)
			return 0;

		/* Parse value. */
		if (!expr->pat_head->parse_smp(elt->sample, smp)) {
			memprintf(err, "unable to parse '%s'", elt->sample);
			free(smp);
			return 0;
		}

	}
	else
		smp = NULL;

	/* initialise pattern */
	memset(&pattern, 0, sizeof(pattern));
	pattern.smp = smp;
	pattern.ref = elt;

	/* parse pattern */
	if (!expr->pat_head->parse(elt->pattern, &pattern, expr->mflags, err)) {
		free(smp);
		return 0;
	}

	/* index pattern */
	if (!expr->pat_head->index(expr, &pattern, err)) {
		free(smp);
		return 0;
	}

	return 1;
}

/* This function adds entry to <ref>. It can failed with memory error. The new
 * entry is added at all the pattern_expr registered in this reference. The
 * function stop on the first error encountered. It returns 0 and err is
 * filled. If an error is encountered, the complete add operation is cancelled.
 * If the insertion is a success the function returns 1.
 */
int pat_ref_add(struct pat_ref *ref,
                const char *pattern, const char *sample,
                char **err)
{
	struct pat_ref_elt *elt;
	struct pattern_expr *expr;

	elt = malloc(sizeof(*elt));
	if (!elt) {
		memprintf(err, "out of memory error");
		return 0;
	}

	elt->line = -1;

	elt->pattern = strdup(pattern);
	if (!elt->pattern) {
		free(elt);
		memprintf(err, "out of memory error");
		return 0;
	}

	if (sample) {
		elt->sample = strdup(sample);
		if (!elt->sample) {
			free(elt->pattern);
			free(elt);
			memprintf(err, "out of memory error");
			return 0;
		}
	}
	else
		elt->sample = NULL;

	LIST_ADDQ(&ref->head, &elt->list);

	list_for_each_entry(expr, &ref->pat, list) {
		if (!pat_ref_push(elt, expr, 0, err)) {
			/* If the insertion fails, try to delete all the added entries. */
			pat_ref_delete_by_id(ref, elt);
			return 0;
		}
	}
	return 1;
}

/* This function prune <ref>, replace all reference by the references
 * of <replace>, and reindex all the news values.
 *
 * The pattern are loaded in best effort and the errors are ignored,
 * but writed in the logs.
 */
void pat_ref_reload(struct pat_ref *ref, struct pat_ref *replace)
{
	struct pattern_expr *expr;
	struct pat_ref_elt *elt;
	char *err = NULL;

	pat_ref_prune(ref);

	LIST_ADD(&replace->head, &ref->head);
	LIST_DEL(&replace->head);

	list_for_each_entry(elt, &ref->head, list) {
		list_for_each_entry(expr, &ref->pat, list) {
			if (!pat_ref_push(elt, expr, 0, &err)) {
				send_log(NULL, LOG_NOTICE, "%s", err);
				free(err);
				err = NULL;
			}
		}
	}
}

/* This function prune all entries of <ref>. This function
 * prune the associated pattern_expr.
 */
void pat_ref_prune(struct pat_ref *ref)
{
	struct pat_ref_elt *elt, *safe;
	struct pattern_expr *expr;

	list_for_each_entry_safe(elt, safe, &ref->head, list) {
		LIST_DEL(&elt->list);
		free(elt->pattern);
		free(elt->sample);
		free(elt);
	}

	list_for_each_entry(expr, &ref->pat, list)
		expr->pat_head->prune(expr);
}

/* This function lookup for existing reference <ref> in pattern_head <head>. */
struct pattern_expr *pattern_lookup_expr(struct pattern_head *head, struct pat_ref *ref)
{
	struct pattern_expr_list *expr;

	list_for_each_entry(expr, &head->head, list)
		if (expr->expr->ref == ref)
			return expr->expr;
	return NULL;
}

/* This function create new pattern_expr associated to the reference <ref>.
 * <ref> can be NULL. If an error is occured, the function returns NULL and
 * <err> is filled. Otherwise, the function returns new pattern_expr linked
 * with <head> and <ref>.
 */
struct pattern_expr *pattern_new_expr(struct pattern_head *head, struct pat_ref *ref, char **err)
{
	struct pattern_expr *expr;
	struct pattern_expr_list *list;

	/* Memory and initialization of the chain element. */
	list = malloc(sizeof(*list));
	if (!list) {
		memprintf(err, "out of memory");
		return NULL;
	}

	/* Look for existing similar expr. No that only the index, parse and
	 * parse_smp function must be identical for having similar pattern.
	 * The other function depends of theses first.
	 */
	if (ref) {
		list_for_each_entry(expr, &ref->pat, list)
			if (expr->pat_head->index     == head->index &&
			    expr->pat_head->parse     == head->parse &&
			    expr->pat_head->parse_smp == head->parse_smp)
				break;
		if (&expr->list == &ref->pat)
			expr = NULL;
	}
	else
		expr = NULL;

	/* If no similar expr was found, we create new expr. */
	if (!expr) {
		/* Get a lot of memory for the expr struct. */
		expr = malloc(sizeof(*expr));
		if (!expr) {
			memprintf(err, "out of memory");
			return NULL;
		}

		/* Initialize this new expr. */
		pattern_init_expr(expr);

		/* This new pattern expression reference one of his heads. */
		expr->pat_head = head;

		/* Link with ref, or to self to facilitate LIST_DEL() */
		if (ref)
			LIST_ADDQ(&ref->pat, &expr->list);
		else
			LIST_INIT(&expr->list);

		expr->ref = ref;

		/* We must free this pattern if it is no more used. */
		list->do_free = 1;
	}
	else {
		/* If the pattern used already exists, it is already linked
		 * with ref and we must not free it.
		 */
		list->do_free = 0;
	}

	/* The new list element reference the pattern_expr. */
	list->expr = expr;

	/* Link the list element with the pattern_head. */
	LIST_ADDQ(&head->head, &list->list);
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
 * Return non-zero in case of succes, otherwise 0.
 */
int pat_ref_read_from_file_smp(struct pat_ref *ref, const char *filename, char **err)
{
	FILE *file;
	char *c;
	int ret = 0;
	int line = 0;
	char *key_beg;
	char *key_end;
	char *value_beg;
	char *value_end;

	file = fopen(filename, "r");
	if (!file) {
		memprintf(err, "failed to open pattern file <%s>", filename);
		return 0;
	}

	/* now parse all patterns. The file may contain only one pattern
	 * followed by one value per line. The start spaces, separator spaces
	 * and and spaces are stripped. Each can contain comment started by '#'
	 */
	while (fgets(trash.str, trash.size, file) != NULL) {
		line++;
		c = trash.str;

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

	/* succes */
	ret = 1;

 out_close:
	fclose(file);
	return ret;
}

/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 */
int pat_ref_read_from_file(struct pat_ref *ref, const char *filename, char **err)
{
	FILE *file;
	char *c;
	char *arg;
	int ret = 0;
	int line = 0;

	file = fopen(filename, "r");
	if (!file) {
		memprintf(err, "failed to open pattern file <%s>", filename);
		return 0;
	}

	/* now parse all patterns. The file may contain only one pattern per
	 * line. If the line contains spaces, they will be part of the pattern.
	 * The pattern stops at the first CR, LF or EOF encountered.
	 */
	while (fgets(trash.str, trash.size, file) != NULL) {
		line++;
		c = trash.str;

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
			memprintf(err, "out of memory when loading patterns from file <%s>", filename);
			goto out_close;
		}
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

	/* Lookup for the existing reference. */
	ref = pat_ref_lookup(filename);

	/* If the reference doesn't exists, create it and load associated file. */
	if (!ref) {
		chunk_printf(&trash,
		             "pattern loaded from file '%s' used by %s at file '%s' line %d",
		             filename, refflags & PAT_REF_MAP ? "map" : "acl", file, line);

		ref = pat_ref_new(filename, trash.str, refflags);
		if (!ref) {
			memprintf(err, "out of memory");
			return 0;
		}

		if (load_smp) {
			ref->flags |= PAT_REF_SMP;
			if (!pat_ref_read_from_file_smp(ref, filename, err))
				return 0;
		}
		else {
			if (!pat_ref_read_from_file(ref, filename, err))
				return 0;
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
		ref->display = strdup(trash.str);
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
		expr = pattern_new_expr(head, ref, err);
		if (!expr)
			return 0;
		expr->mflags = patflags;
	}

	/* Load reference content in the pattern expression. */
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
 * to sample <smp>. The function returns NULL if the sample dont match. It returns
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
			static_pattern.smp = NULL;
			static_pattern.ref = NULL;
			static_pattern.sflags = 0;
			static_pattern.type = SMP_T_UINT;
			static_pattern.val.i = 1;
		}
		return &static_pattern;
	}

	/* convert input to string */
	if (!sample_convert(smp, head->expect_type))
		return NULL;

	list_for_each_entry(list, &head->head, list) {
		pat = head->match(smp, list->expr, fill);
		if (pat)
			return pat;
	}
	return NULL;
}

/* This function prune the pattern expression. */
void pattern_prune(struct pattern_head *head)
{
	struct pattern_expr_list *list, *safe;

	list_for_each_entry_safe(list, safe, &head->head, list) {
		LIST_DEL(&list->list);
		if (list->do_free) {
			LIST_DEL(&list->expr->list);
			head->prune(list->expr);
			free(list->expr);
		}
		free(list);
	}
}

/* This function lookup for a pattern matching the <key> and return a
 * pointer to a pointer of the sample stoarge. If the <key> dont match,
 * the function returns NULL. If the key cannot be parsed, the function
 * fill <err>.
 */
struct sample_storage **pattern_find_smp(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	struct ebmb_node *node;
	struct pattern_tree *elt;
	struct pattern_list *pat;

	for (node = ebmb_first(&expr->pattern_tree);
	     node;
	     node = ebmb_next(node)) {
		elt = container_of(node, struct pattern_tree, node);
		if (elt->ref == ref)
			return &elt->smp;
	}

	for (node = ebmb_first(&expr->pattern_tree_2);
	     node;
	     node = ebmb_next(node)) {
		elt = container_of(node, struct pattern_tree, node);
		if (elt->ref == ref)
			return &elt->smp;
	}

	list_for_each_entry(pat, &expr->patterns, list)
		if (pat->pat.ref == ref)
			return &pat->pat.smp;

	return NULL;
}

/* This function search all the pattern matching the <key> and delete it.
 * If the parsing of the input key fails, the function returns 0 and the
 * <err> is filled, else return 1;
 */
int pattern_delete(struct pattern_expr *expr, struct pat_ref_elt *ref)
{
	expr->pat_head->delete(expr, ref);
	return 1;
}

/* This function finalize the configuration parsing. Its set all the
 * automatic ids
 */
void pattern_finalize_config(void)
{
	int i = 0;
	struct pat_ref *ref, *ref2, *ref3;
	struct list pr = LIST_HEAD_INIT(pr);

	list_for_each_entry(ref, &pattern_reference, list) {
		if (ref->unique_id == -1) {
			/* Look for the first free id. */
			while (1) {
				list_for_each_entry(ref2, &pattern_reference, list) {
					if (ref2->unique_id == i) {
						i++;
						break;
					}
				}
				if (&ref2->list == &pattern_reference)
					break;
			}

			/* Uses the unique id and increment it for the next entry. */
			ref->unique_id = i;
			i++;
		}
	}

	/* This sort the reference list by id. */
	list_for_each_entry_safe(ref, ref2, &pattern_reference, list) {
		LIST_DEL(&ref->list);
		list_for_each_entry(ref3, &pr, list) {
			if (ref->unique_id < ref3->unique_id) {
				LIST_ADDQ(&ref3->list, &ref->list);
				break;
			}
		}
		if (&ref3->list == &pr)
			LIST_ADDQ(&pr, &ref->list);
	}

	/* swap root */
	LIST_ADD(&pr, &pattern_reference);
	LIST_DEL(&pr);
}
