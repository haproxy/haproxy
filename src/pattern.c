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

int (*pat_parse_fcts[PAT_MATCH_NUM])(const char *, struct pattern *, char **) = {
	[PAT_MATCH_FOUND] = pat_parse_nothing,
	[PAT_MATCH_BOOL]  = pat_parse_nothing,
	[PAT_MATCH_INT]   = pat_parse_int,
	[PAT_MATCH_IP]    = pat_parse_ip,
	[PAT_MATCH_BIN]   = pat_parse_bin,
	[PAT_MATCH_LEN]   = pat_parse_len,
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
	[PAT_MATCH_BEG]   = pat_idx_list_str,
	[PAT_MATCH_SUB]   = pat_idx_list_str,
	[PAT_MATCH_DIR]   = pat_idx_list_str,
	[PAT_MATCH_DOM]   = pat_idx_list_str,
	[PAT_MATCH_END]   = pat_idx_list_str,
	[PAT_MATCH_REG]   = pat_idx_list_reg,
};

enum pat_match_res (*pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern *) = {
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
	[PAT_MATCH_BIN]   = SMP_T_CBIN,
	[PAT_MATCH_LEN]   = SMP_T_CSTR,
	[PAT_MATCH_STR]   = SMP_T_CSTR,
	[PAT_MATCH_BEG]   = SMP_T_CSTR,
	[PAT_MATCH_SUB]   = SMP_T_CSTR,
	[PAT_MATCH_DIR]   = SMP_T_CSTR,
	[PAT_MATCH_DOM]   = SMP_T_CSTR,
	[PAT_MATCH_END]   = SMP_T_CSTR,
	[PAT_MATCH_REG]   = SMP_T_CSTR,
};

/*
 *
 * The following functions are not exported and are used by internals process
 * of pattern matching
 *
 */

/* Lookup an IPv4 address in the expression's pattern tree using the longest
 * match method. The node is returned if it exists, otherwise NULL.
 */
static void *pat_lookup_ip(struct sample *smp, struct pattern_expr *expr)
{
	struct in_addr *s;

	if (smp->type != SMP_T_IPV4)
		return PAT_NOMATCH;

	s = &smp->data.ipv4;
	return ebmb_lookup_longest(&expr->pattern_tree, &s->s_addr);
}

/* Free data allocated by pat_parse_reg */
static void pat_free_reg(void *ptr)
{
	regex_free(ptr);
}

/* Lookup a string in the expression's pattern tree. The node is returned if it
 * exists, otherwise NULL.
 */
static void *pat_lookup_str(struct sample *smp, struct pattern_expr *expr)
{
	/* data are stored in a tree */
	struct ebmb_node *node;
	char prev;

	/* we may have to force a trailing zero on the test pattern */
	prev = smp->data.str.str[smp->data.str.len];
	if (prev)
		smp->data.str.str[smp->data.str.len] = '\0';
	node = ebst_lookup(&expr->pattern_tree, smp->data.str.str);
	if (prev)
		smp->data.str.str[smp->data.str.len] = prev;
	return node;
}

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
int pat_parse_nothing(const char *text, struct pattern *pattern, char **err)
{
	return 1;
}

/* Parse a string. It is allocated and duplicated. */
int pat_parse_str(const char *text, struct pattern *pattern, char **err)
{
	pattern->type = SMP_T_CSTR;
	pattern->expect_type = SMP_T_CSTR;
	pattern->ptr.str = (char *)text;
	pattern->len = strlen(text);
	return 1;
}

/* Parse a binary written in hexa. It is allocated. */
int pat_parse_bin(const char *text, struct pattern *pattern, char **err)
{
	struct chunk *trash;

	pattern->type = SMP_T_CBIN;
	pattern->expect_type = SMP_T_CBIN;
	trash = get_trash_chunk();
	pattern->len = trash->size;
	pattern->ptr.str = trash->str;
	return !!parse_binary(text, &pattern->ptr.str, &pattern->len, err);
}

/* Parse a regex. It is allocated. */
int pat_parse_reg(const char *text, struct pattern *pattern, char **err)
{
	struct chunk *trash;

	trash = get_trash_chunk();
	if (trash->size < sizeof(*pattern->ptr.reg)) {
		memprintf(err, "no space avalaible in the buffer. expect %d, provides %d",
		          (int)sizeof(*pattern->ptr.reg), trash->size);
		return 0;
	}

	pattern->ptr.reg = (struct my_regex *)trash->str;
	pattern->ptr.reg->regstr = (char *)text;
	pattern->freeptrbuf = NULL;

	pattern->expect_type = SMP_T_CSTR;
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
int pat_parse_int(const char *text, struct pattern *pattern, char **err)
{
	const char *ptr = text;

	pattern->type = SMP_T_UINT;
	pattern->expect_type = SMP_T_UINT;

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

int pat_parse_len(const char *text, struct pattern *pattern, char **err)
{
	int ret;

	ret = pat_parse_int(text, pattern, err);
	pattern->expect_type = SMP_T_CSTR;
	return ret;
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
int pat_parse_dotted_ver(const char *text, struct pattern *pattern, char **err)
{
	const char *ptr = text;

	pattern->type = SMP_T_UINT;
	pattern->expect_type = SMP_T_UINT;

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
int pat_parse_ip(const char *text, struct pattern *pattern, char **err)
{
	pattern->expect_type = SMP_T_ADDR;
	if (str2net(text, &pattern->val.ipv4.addr, &pattern->val.ipv4.mask)) {
		pattern->type = SMP_T_IPV4;
		return 1;
	}
	else if (str62net(text, &pattern->val.ipv6.addr, &pattern->val.ipv6.mask)) {
		/* no tree support right now */
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
enum pat_match_res pat_match_nothing(struct sample *smp, struct pattern *pattern)
{
	return PAT_NOMATCH;
}


/* NB: For two strings to be identical, it is required that their lengths match */
enum pat_match_res pat_match_str(struct sample *smp, struct pattern *pattern)
{
	int icase;

	if (pattern->len != smp->data.str.len)
		return PAT_NOMATCH;

	icase = pattern->flags & PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0))
		return PAT_MATCH;
	return PAT_NOMATCH;
}

/* NB: For two binaries buf to be identical, it is required that their lengths match */
enum pat_match_res pat_match_bin(struct sample *smp, struct pattern *pattern)
{
	if (pattern->len != smp->data.str.len)
		return PAT_NOMATCH;

	if (memcmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0)
		return PAT_MATCH;
	return PAT_NOMATCH;
}

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
enum pat_match_res pat_match_reg(struct sample *smp, struct pattern *pattern)
{
	if (regex_exec(pattern->ptr.reg, smp->data.str.str, smp->data.str.len) == 0)
		return PAT_MATCH;
	return PAT_NOMATCH;
}

/* Checks that the pattern matches the beginning of the tested string. */
enum pat_match_res pat_match_beg(struct sample *smp, struct pattern *pattern)
{
	int icase;

	if (pattern->len > smp->data.str.len)
		return PAT_NOMATCH;

	icase = pattern->flags & PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0))
		return PAT_NOMATCH;
	return PAT_MATCH;
}

/* Checks that the pattern matches the end of the tested string. */
enum pat_match_res pat_match_end(struct sample *smp, struct pattern *pattern)
{
	int icase;

	if (pattern->len > smp->data.str.len)
		return PAT_NOMATCH;
	icase = pattern->flags & PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0))
		return PAT_NOMATCH;
	return PAT_MATCH;
}

/* Checks that the pattern is included inside the tested string.
 * NB: Suboptimal, should be rewritten using a Boyer-Moore method.
 */
enum pat_match_res pat_match_sub(struct sample *smp, struct pattern *pattern)
{
	int icase;
	char *end;
	char *c;

	if (pattern->len > smp->data.str.len)
		return PAT_NOMATCH;

	end = smp->data.str.str + smp->data.str.len - pattern->len;
	icase = pattern->flags & PAT_F_IGNORE_CASE;
	if (icase) {
		for (c = smp->data.str.str; c <= end; c++) {
			if (tolower(*c) != tolower(*pattern->ptr.str))
				continue;
			if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0)
				return PAT_MATCH;
		}
	} else {
		for (c = smp->data.str.str; c <= end; c++) {
			if (*c != *pattern->ptr.str)
				continue;
			if (strncmp(pattern->ptr.str, c, pattern->len) == 0)
				return PAT_MATCH;
		}
	}
	return PAT_NOMATCH;
}

/* This one is used by other real functions. It checks that the pattern is
 * included inside the tested string, but enclosed between the specified
 * delimiters or at the beginning or end of the string. The delimiters are
 * provided as an unsigned int made by make_4delim() and match up to 4 different
 * delimiters. Delimiters are stripped at the beginning and end of the pattern.
 */
static int match_word(struct sample *smp, struct pattern *pattern, unsigned int delimiters)
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
	icase = pattern->flags & PAT_F_IGNORE_CASE;
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
enum pat_match_res pat_match_dir(struct sample *smp, struct pattern *pattern)
{
	return match_word(smp, pattern, make_4delim('/', '?', '?', '?'));
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delmiters '/', '?', '.' or ":" or at the beginning or end of
 * the string. Delimiters at the beginning or end of the pattern are ignored.
 */
enum pat_match_res pat_match_dom(struct sample *smp, struct pattern *pattern)
{
	return match_word(smp, pattern, make_4delim('/', '?', '.', ':'));
}

/* Checks that the integer in <test> is included between min and max */
enum pat_match_res pat_match_int(struct sample *smp, struct pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.uint) &&
	    (!pattern->val.range.max_set || smp->data.uint <= pattern->val.range.max))
		return PAT_MATCH;
	return PAT_NOMATCH;
}

/* Checks that the length of the pattern in <test> is included between min and max */
enum pat_match_res pat_match_len(struct sample *smp, struct pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.str.len) &&
	    (!pattern->val.range.max_set || smp->data.str.len <= pattern->val.range.max))
		return PAT_MATCH;
	return PAT_NOMATCH;
}

enum pat_match_res pat_match_ip(struct sample *smp, struct pattern *pattern)
{
	unsigned int v4; /* in network byte order */
	struct in6_addr *v6;
	int bits, pos;
	struct in6_addr tmp6;

	if (pattern->type == SMP_T_IPV4) {
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
				return PAT_NOMATCH;
		}
		else
			return PAT_NOMATCH;

		if (((v4 ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
			return PAT_MATCH;
		else
			return PAT_NOMATCH;
	}
	else if (pattern->type == SMP_T_IPV6) {
		if (smp->type == SMP_T_IPV4) {
			/* Convert the IPv4 sample address to IPv4 with the
			 * mapping method using the ::ffff: prefix.
			 */
			memset(&tmp6, 0, 10);
			*(uint16_t*)&tmp6.s6_addr[10] = htons(0xffff);
			*(uint32_t*)&tmp6.s6_addr[12] = smp->data.ipv4.s_addr;
			v6 = &tmp6;
		}
		else if (smp->type == SMP_T_IPV6) {
			v6 = &smp->data.ipv6;
		}
		else {
			return PAT_NOMATCH;
		}

		bits = pattern->val.ipv6.mask;
		for (pos = 0; bits > 0; pos += 4, bits -= 32) {
			v4 = *(uint32_t*)&v6->s6_addr[pos] ^ *(uint32_t*)&pattern->val.ipv6.addr.s6_addr[pos];
			if (bits < 32)
				v4 &= htonl((~0U) << (32-bits));
			if (v4)
				return PAT_NOMATCH;
		}
		return PAT_MATCH;
	}
	return PAT_NOMATCH;
}

/* NB: does nothing if <pat> is NULL */
void pattern_free(struct pattern_list *pat)
{
	if (!pat)
		return;

	if (pat->pat.ptr.ptr) {
		if (pat->pat.freeptrbuf)
			pat->pat.freeptrbuf(pat->pat.ptr.ptr);

		free(pat->pat.ptr.ptr);
	}

	free(pat->pat.smp);
	free(pat);
}

void free_pattern_list(struct list *head)
{
	struct pattern_list *pat, *tmp;
	list_for_each_entry_safe(pat, tmp, head, list)
		pattern_free(pat);
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

void pattern_prune_expr(struct pattern_expr *expr)
{
	free_pattern_list(&expr->patterns);
	free_pattern_tree(&expr->pattern_tree);
	LIST_INIT(&expr->patterns);
}

void pattern_init_expr(struct pattern_expr *expr)
{
	LIST_INIT(&expr->patterns);
	expr->pattern_tree = EB_ROOT_UNIQUE;
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
	if (!regex_comp(pat->ptr.reg->regstr, patl->pat.ptr.reg, !(patl->pat.flags & PAT_F_IGNORE_CASE), 0, err)) {
		free(patl);
		free(patl->pat.ptr.reg);
		return 0;
	}

	/* free pattern method */
	patl->pat.freeptrbuf = &pat_free_reg;

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

			/* FIXME: insert <addr>/<mask> into the tree here */
			memcpy(node->node.key, &pat->val.ipv4.addr, 4); /* network byte order */
			node->node.node.pfx = mask;
			if (ebmb_insert_prefix(&expr->pattern_tree, &node->node, 4) != &node->node)
				free(node); /* was a duplicate */

			/* that's ok */
			return 1;
		}
	}

	/* If the value cannot be indexed, just add it to the list */
	return pat_idx_list_val(expr, pat, err);
}

int pat_idx_tree_str(struct pattern_expr *expr, struct pattern *pat, char **err)
{
	int len;
	struct pattern_tree *node;

	/* Only string can be indexed */
	if (pat->type != SMP_T_CSTR && pat->type != SMP_T_STR) {
		memprintf(err, "internal error: string expected, but the type is '%s'",
		          smp_to_type[pat->type]);
		return 0;
	}

	/* If the flag PAT_F_IGNORE_CASE is set, we cannot use trees */
	if (pat->flags & PAT_F_IGNORE_CASE)
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

	/* copy the string */
	memcpy(node->node.key, pat->ptr.str, len);

	/* index the new node */
	if (ebst_insert(&expr->pattern_tree, &node->node) != &node->node)
		free(node); /* was a duplicate */

	/* that's ok */
	return 1;
}

/* return 1 if the process is ok
 * return -1 if the parser fail. The err message is filled.
 * return -2 if out of memory
 */
int pattern_register(struct pattern_expr *expr, const char *arg,
                     struct sample_storage *smp,
                     int patflags, char **err)
{
	int ret;
	struct pattern pattern;

	/* initialise pattern */
	memset(&pattern, 0, sizeof(pattern));
	pattern.flags = patflags;
	pattern.smp = smp;

	/* parse pattern */
	ret = expr->parse(arg, &pattern, err);
	if (!ret)
		return 0;

	/* index pattern */
	if (!expr->index(expr, &pattern, err))
		return 0;

	return 1;
}

/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 */
int pattern_read_from_file(struct pattern_expr *expr,
                                const char *filename, int patflags,
                                char **err)
{
	FILE *file;
	char *c;
	char *arg;
	int ret = 0;
	int line = 0;
	int code;

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

		code = pattern_register(expr, arg, NULL, patflags, err);
		if (code == -2) {
			memprintf(err, "out of memory when loading patterns from file <%s>", filename);
			goto out_close;
		}
		else if (code < 0) {
			memprintf(err, "%s when loading patterns from file <%s>", *err, filename);
			goto out_close;
		}
	}

	ret = 1; /* success */

 out_close:
	fclose(file);
	return ret;
}

/* This function matches a sample <smp> against a set of patterns presented in
 * pattern expression <expr>. Upon success, if <sample> is not NULL, it is fed
 * with the pointer associated with the matching pattern. This function returns
 * PAT_NOMATCH or PAT_MATCH.
 */
enum pat_match_res pattern_exec_match(struct pattern_expr *expr, struct sample *smp,
                                      struct sample_storage **sample,
                                      struct pattern **pat, struct pattern_tree **idx_elt)
{
	enum pat_match_res pat_res = PAT_NOMATCH;
	struct pattern_list *pattern;
	struct ebmb_node *node = NULL;
	struct pattern_tree *elt;

	if (expr->match == pat_match_nothing) {
		if (smp->data.uint)
			pat_res |= PAT_MATCH;
		else
			pat_res |= PAT_NOMATCH;
	}
	else if (!expr->match) {
		/* just check for existence */
		pat_res |= PAT_MATCH;
	}
	else {
		if (!eb_is_empty(&expr->pattern_tree)) {
			/* a tree is present, let's check what type it is */
			if (expr->match == pat_match_str) {
				if (sample_convert(smp, SMP_T_STR))
					node = pat_lookup_str(smp, expr);
			}
			else if (expr->match == pat_match_ip) {
				if (sample_convert(smp, SMP_T_IPV4))
					node = pat_lookup_ip(smp, expr);
			}
			if (node) {
				pat_res |= PAT_MATCH;
				elt = ebmb_entry(node, struct pattern_tree, node);
				if (sample)
					*sample = elt->smp;
				if (idx_elt)
					*idx_elt = elt;
			}
		}

		/* call the match() function for all tests on this value */
		list_for_each_entry(pattern, &expr->patterns, list) {
			if (pat_res == PAT_MATCH)
				break;
			if (sample_convert(smp, pattern->pat.expect_type))
				pat_res |= expr->match(smp, &pattern->pat);
			if (sample)
				*sample = pattern->pat.smp;
			if (pat)
				*pat = &pattern->pat;
		}
	}

	return pat_res;
}

/* This function browse the pattern expr <expr> to lookup the key <key>. On
 * error it returns 0. On success, it returns 1 and fills either <pat_elt>
 * or <idx_elt> with the respectively matched pointers, and the other one with
 * NULL. Pointers are not set if they're passed as NULL.
 */
int pattern_lookup(const char *key, struct pattern_expr *expr,
                   struct pattern_list **pat_elt, struct pattern_tree **idx_elt, char **err)
{
	struct pattern pattern;
	struct pattern_list *pat;
	struct ebmb_node *node;
	struct pattern_tree *elt;
	unsigned int mask = 0;

	/* no real pattern */
	if (!expr->match || expr->match == pat_match_nothing)
		return 0;

	/* build lookup pattern */
	if (!expr->parse(key, &pattern, NULL))
		return 0;

	pat = NULL;
	elt = NULL;

	/* Try to look up the tree first. IPv6 is not indexed */
	if (!eb_is_empty(&expr->pattern_tree) && pattern.type != SMP_T_IPV6) {
		/* Check the pattern type */
		if (pattern.type != SMP_T_STR &&
		    pattern.type != SMP_T_CSTR &&
		    pattern.type != SMP_T_IPV4) {
			memprintf(err, "Unexpected pattern type.");
			return 0;
		}

		/* Convert mask. If the mask is not contiguous, ignore the lookup
		 * in the tree, and browse the list.
		 */
		if (expr->match == pat_match_ip) {
			mask = ntohl(pattern.val.ipv4.mask.s_addr);
			if (mask + (mask & -mask) != 0)
				goto browse_list;
			mask = mask ? 33 - flsnz(mask & -mask) : 0; /* equals cidr value */
		}

		/* browse each node of the tree, and check string */
		if (expr->match == pat_match_str) {
			for (node = ebmb_first(&expr->pattern_tree);
			     node;
			     node = ebmb_next(node)) {
				elt = container_of(node, struct pattern_tree, node);
				if (strcmp(pattern.ptr.str, (char *)elt->node.key) == 0)
					goto found;
			}
		}
		else if (expr->match == pat_match_ip) {
			for (node = ebmb_first(&expr->pattern_tree);
			     node;
			     node = ebmb_next(node)) {
				elt = container_of(node, struct pattern_tree, node);
				if (elt->node.node.pfx == mask &&
				    memcmp(&pattern.val.ipv4.addr.s_addr, elt->node.key, 4) == 0)
					goto found;
			}
		}
	}

browse_list:
	elt = NULL;
	if (expr->parse == pat_parse_int ||
	         expr->parse == pat_parse_len) {
		list_for_each_entry(pat, &expr->patterns, list) {
			if (pat->pat.flags & PAT_F_TREE)
				continue;
			if (pattern.val.range.min_set != pat->pat.val.range.min_set)
				continue;
			if (pattern.val.range.max_set != pat->pat.val.range.max_set)
				continue;
			if (pattern.val.range.min_set &&
			    pattern.val.range.min != pat->pat.val.range.min)
				continue;
			if (pattern.val.range.max_set &&
			    pattern.val.range.max != pat->pat.val.range.max)
				continue;
			goto found;
		}
	}
	else if (expr->parse == pat_parse_ip) {
		list_for_each_entry(pat, &expr->patterns, list) {
			if (pat->pat.flags & PAT_F_TREE)
				continue;
			if (pattern.type != pat->pat.type)
				continue;
			if (pattern.type == SMP_T_IPV4 &&
			    memcmp(&pattern.val.ipv4.addr, &pat->pat.val.ipv4.addr, sizeof(pat->pat.val.ipv4.addr)) != 0)
				continue;
			if (pattern.type == SMP_T_IPV4 &&
			    memcmp(&pattern.val.ipv4.mask, &pat->pat.val.ipv4.mask, sizeof(pat->pat.val.ipv4.addr)) != 0)
				continue;
			if (pattern.type == SMP_T_IPV6 &&
			    memcmp(&pattern.val.ipv6.addr, &pat->pat.val.ipv6.addr, sizeof(pat->pat.val.ipv6.addr)) != 0)
				continue;
			if (pattern.type == SMP_T_IPV6 &&
			    pattern.val.ipv6.mask != pat->pat.val.ipv6.mask)
				continue;
			goto found;
		}
	}
	else if (expr->parse == pat_parse_str) {
		list_for_each_entry(pat, &expr->patterns, list) {
			if (pat->pat.flags & PAT_F_TREE)
				continue;
			if (pattern.len != pat->pat.len)
				continue;
			if (pat->pat.flags & PAT_F_IGNORE_CASE) {
				if (strncasecmp(pattern.ptr.str, pat->pat.ptr.str, pat->pat.len) != 0)
					continue;
			}
			else {
				if (strncmp(pattern.ptr.str, pat->pat.ptr.str, pat->pat.len) != 0)
					continue;
			}
			goto found;
		}
	}
	else if (expr->parse == pat_parse_bin) {
		list_for_each_entry(pat, &expr->patterns, list) {
			if (pat->pat.flags & PAT_F_TREE)
				continue;
			if (pattern.len != pat->pat.len)
				continue;
			if (memcmp(pattern.ptr.ptr, pat->pat.ptr.ptr, pat->pat.len) != 0)
				continue;
			goto found;
		}
	}
	else if (expr->parse == pat_parse_reg) {
		list_for_each_entry(pat, &expr->patterns, list) {
			if (pat->pat.flags & PAT_F_TREE)
				continue;
			if (pat->pat.flags & PAT_F_IGNORE_CASE) {
				if (strcasecmp(pattern.ptr.reg->regstr, pat->pat.ptr.reg->regstr) != 0)
					continue;
			}
			else {
				if (strcmp(pattern.ptr.reg->regstr, pat->pat.ptr.reg->regstr) != 0)
					continue;
			}
			goto found;
		}
	}

	/* if we get there, we didn't find the pattern */
	return 0;
found:
	if (idx_elt)
		*idx_elt = elt;

	if (pat_elt)
		*pat_elt = pat;

	return 1;
}
