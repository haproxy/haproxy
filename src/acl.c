/*
 * ACL management functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <proto/acl.h>

#include <types/acl.h>
#include <types/proxy.h>
#include <types/session.h>

/* List head of all known ACL keywords */
static struct acl_kw_list acl_keywords = {
	.list = LIST_HEAD_INIT(acl_keywords.list)
};


/* This one always returns 1 because its only purpose is to check that the
 * value is present, which is already checked by getval().
 */
int acl_match_pst(struct acl_test *test, struct acl_pattern *pattern)
{
	return 1;
}

/* NB: For two strings to be identical, it is required that their lengths match */
int acl_match_str(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len != test->len)
		return 0;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, test->ptr, test->len) == 0) ||
	    (!icase && strncmp(pattern->ptr.str, test->ptr, test->len) == 0))
		return 1;
	return 0;
}

/* Executes a regex. It needs to change the data. If it is marked READ_ONLY
 * then it will be allocated and duplicated in place so that others may use
 * it later on. Note that this is embarrassing because we always try to avoid
 * allocating memory at run time.
 */
int acl_match_reg(struct acl_test *test, struct acl_pattern *pattern)
{
	char old_char;
	int ret;

	if (unlikely(test->flags & ACL_TEST_F_READ_ONLY)) {
		char *new_str;

		new_str = calloc(1, test->len + 1);
		if (!new_str)
			return 0;

		memcpy(new_str, test->ptr, test->len);
		new_str[test->len] = 0;
		if (test->flags & ACL_TEST_F_MUST_FREE)
			free(test->ptr);
		test->ptr = new_str;
		test->flags |= ACL_TEST_F_MUST_FREE;
		test->flags &= ~ACL_TEST_F_READ_ONLY;
	}

	old_char = test->ptr[test->len];
	test->ptr[test->len] = 0;

	if (regexec(pattern->ptr.reg, test->ptr, 0, NULL, 0) == 0)
		ret = 1;
	else
		ret = 0;

	test->ptr[test->len] = old_char;
	return ret;
}

/* Checks that the pattern matches the beginning of the tested string. */
int acl_match_beg(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > test->len)
		return 0;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, test->ptr, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, test->ptr, pattern->len) != 0))
		return 0;
	return 1;
}

/* Checks that the pattern matches the end of the tested string. */
int acl_match_end(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > test->len)
		return 0;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, test->ptr + test->len - pattern->len, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, test->ptr + test->len - pattern->len, pattern->len) != 0))
		return 0;
	return 1;
}

/* Checks that the pattern is included inside the tested string.
 * NB: Suboptimal, should be rewritten using a Boyer-Moore method.
 */
int acl_match_sub(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;
	char *end;
	char *c;

	if (pattern->len > test->len)
		return 0;

	end = test->ptr + test->len - pattern->len;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if (icase) {
		for (c = test->ptr; c <= end; c++) {
			if (tolower(*c) != tolower(*pattern->ptr.str))
				continue;
			if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0)
				return 1;
		}
	} else {
		for (c = test->ptr; c <= end; c++) {
			if (*c != *pattern->ptr.str)
				continue;
			if (strncmp(pattern->ptr.str, c, pattern->len) == 0)
				return 1;
		}
	}
	return 0;
}

/* This one is used by other real functions. It checks that the pattern is
 * included inside the tested string, but enclosed between the specified
 * delimitor, or a '/' or a '?' or at the beginning or end of the string.
 * The delimitor is stripped at the beginning or end of the pattern.
 */
static int match_word(struct acl_test *test, struct acl_pattern *pattern, char delim)
{
	int may_match, icase;
	char *c, *end;
	char *ps;
	int pl;

	pl = pattern->len;
	ps = pattern->ptr.str;
	while (pl > 0 && (*ps == delim || *ps == '/' || *ps == '?')) {
		pl--;
		ps++;
	}

	while (pl > 0 &&
	       (ps[pl - 1] == delim || ps[pl - 1] == '/' || ps[pl - 1] == '?'))
		pl--;

	if (pl > test->len)
		return 0;

	may_match = 1;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	end = test->ptr + test->len - pl;
	for (c = test->ptr; c <= end; c++) {
		if (*c == '/' || *c == delim || *c == '?') {
			may_match = 1;
			continue;
		}

		if (!may_match)
			continue;

		if (icase) {
			if ((tolower(*c) == tolower(*ps)) &&
			    (strncasecmp(ps, c, pl) == 0) &&
			    (c == end || c[pl] == '/' || c[pl] == delim || c[pl] == '?'))
				return 1;
		} else {
			if ((*c == *ps) &&
			    (strncmp(ps, c, pl) == 0) &&
			    (c == end || c[pl] == '/' || c[pl] == delim || c[pl] == '?'))
				return 1;
		}
		may_match = 0;
	}
	return 0;
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between slashes or at the beginning or end of the string. Slashes at the
 * beginning or end of the pattern are ignored.
 */
int acl_match_dir(struct acl_test *test, struct acl_pattern *pattern)
{
	return match_word(test, pattern, '/');
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between dots or at the beginning or end of the string. Dots at the beginning
 * or end of the pattern are ignored.
 */
int acl_match_dom(struct acl_test *test, struct acl_pattern *pattern)
{
	return match_word(test, pattern, '.');
}

/* Checks that the integer in <test> is included between min and max */
int acl_match_int(struct acl_test *test, struct acl_pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= test->i) &&
	    (!pattern->val.range.max_set || test->i <= pattern->val.range.max))
		return 1;
	return 0;
}

int acl_match_ip(struct acl_test *test, struct acl_pattern *pattern)
{
	struct in_addr *s;

	if (test->i != AF_INET)
		return 0;

	s = (void *)test->ptr;
	if (((s->s_addr ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
		return 1;
	return 0;
}

/* Parse a string. It is allocated and duplicated. */
int acl_parse_str(const char **text, struct acl_pattern *pattern, int *opaque)
{
	int len;

	len  = strlen(*text);
	pattern->ptr.str = strdup(*text);
	if (!pattern->ptr.str)
		return 0;
	pattern->len = len;
	return 1;
}

/* Parse a regex. It is allocated. */
int acl_parse_reg(const char **text, struct acl_pattern *pattern, int *opaque)
{
	regex_t *preg;
	int icase;

	preg = calloc(1, sizeof(regex_t));

	if (!preg)
		return 0;

	icase = (pattern->flags & ACL_PAT_F_IGNORE_CASE) ? REG_ICASE : 0;
	if (regcomp(preg, *text, REG_EXTENDED | REG_NOSUB | icase) != 0) {
		free(preg);
		return 0;
	}

	pattern->ptr.reg = preg;
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
 */
int acl_parse_int(const char **text, struct acl_pattern *pattern, int *opaque)
{
	signed long long i;
	unsigned int j, last, skip = 0;
	const char *ptr = *text;


	while (!isdigit(*ptr)) {
		if      (strcmp(ptr, "eq") == 0) *opaque = 0;
		else if (strcmp(ptr, "gt") == 0) *opaque = 1;
		else if (strcmp(ptr, "ge") == 0) *opaque = 2;
		else if (strcmp(ptr, "lt") == 0) *opaque = 3;
		else if (strcmp(ptr, "le") == 0) *opaque = 4;
		else
			return 0;

		skip++;
		ptr = text[skip];
	}

	last = i = 0;
	while (1) {
                j = *ptr++;
		if ((j == '-' || j == ':') && !last) {
			last++;
			pattern->val.range.min = i;
			i = 0;
			continue;
		}
		j -= '0';
                if (j > 9)
			// also catches the terminating zero
                        break;
                i *= 10;
                i += j;
        }

	if (last && *opaque >= 1 && *opaque <= 4)
		/* having a range with a min or a max is absurd */
		return 0;

	if (!last)
		pattern->val.range.min = i;
	pattern->val.range.max = i;

	switch (*opaque) {
	case 0: /* eq */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 1;
		break;
	case 1: /* gt */
		pattern->val.range.min++; /* gt = ge + 1 */
	case 2: /* ge */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 0;
		break;
	case 3: /* lt */
		pattern->val.range.max--; /* lt = le - 1 */
	case 4: /* le */
		pattern->val.range.min_set = 0;
		pattern->val.range.max_set = 1;
		break;
	}
	return skip + 1;
}

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int acl_parse_ip(const char **text, struct acl_pattern *pattern, int *opaque)
{
	if (str2net(*text, &pattern->val.ipv4.addr, &pattern->val.ipv4.mask))
		return 1;
	else
		return 0;
}

/*
 * Registers the ACL keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void acl_register_keywords(struct acl_kw_list *kwl)
{
	LIST_ADDQ(&acl_keywords.list, &kwl->list);
}

/*
 * Unregisters the ACL keyword list <kwl> from the list of valid keywords.
 */
void acl_unregister_keywords(struct acl_kw_list *kwl)
{
	LIST_DEL(&kwl->list);
	LIST_INIT(&kwl->list);
}

/* Return a pointer to the ACL <name> within the list starting at <head>, or
 * NULL if not found.
 */
struct acl *find_acl_by_name(const char *name, struct list *head)
{
	struct acl *acl;
	list_for_each_entry(acl, head, list) {
		if (strcmp(acl->name, name) == 0)
			return acl;
	}
	return NULL;
}

/* Return a pointer to the ACL keyword <kw>, or NULL if not found. Note that if
 * <kw> contains an opening parenthesis, only the left part of it is checked.
 */
struct acl_keyword *find_acl_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct acl_kw_list *kwl;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &acl_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0)
				return &kwl->kw[index];
		}
	}
	return NULL;
}

static void free_pattern(struct acl_pattern *pat)
{
	if (pat->ptr.ptr)
		free(pat->ptr.ptr);
	free(pat);
}

static void free_pattern_list(struct list *head)
{
	struct acl_pattern *pat, *tmp;
	list_for_each_entry_safe(pat, tmp, head, list)
		free_pattern(pat);
}

static struct acl_expr *prune_acl_expr(struct acl_expr *expr)
{
	free_pattern_list(&expr->patterns);
	LIST_INIT(&expr->patterns);
	if (expr->arg.str)
		free(expr->arg.str);
	expr->kw->use_cnt--;
	return expr;
}

/* Parse an ACL expression starting at <args>[0], and return it.
 * Right now, the only accepted syntax is :
 * <subject> [<value>...]
 */
struct acl_expr *parse_acl_expr(const char **args)
{
	__label__ out_return, out_free_expr, out_free_pattern;
	struct acl_expr *expr;
	struct acl_keyword *aclkw;
	struct acl_pattern *pattern;
	int opaque, patflags;
	const char *arg;

	aclkw = find_acl_kw(args[0]);
	if (!aclkw || !aclkw->parse)
		goto out_return;

	expr = (struct acl_expr *)calloc(1, sizeof(*expr));
	if (!expr)
		goto out_return;

	expr->kw = aclkw;
	aclkw->use_cnt++;
	LIST_INIT(&expr->patterns);
	expr->arg.str = NULL;
	expr->arg_len = 0;

	arg = strchr(args[0], '(');
	if (arg != NULL) {
		char *end, *arg2;
		/* there is an argument in the form "subject(arg)" */
		arg++;
		end = strchr(arg, ')');
		if (!end)
			goto out_free_expr;
		arg2 = (char *)calloc(1, end - arg + 1);
		if (!arg2)
			goto out_free_expr;
		memcpy(arg2, arg, end - arg);
		arg2[end-arg] = '\0';
		expr->arg_len = end - arg;
		expr->arg.str = arg2;
	}

	args++;

	/* check for options before patterns. Supported options are :
	 *   -i : ignore case for all patterns by default
	 *   -f : read patterns from those files
	 *   -- : everything after this is not an option
	 */
	patflags = 0;
	while (**args == '-') {
		if ((*args)[1] == 'i')
			patflags |= ACL_PAT_F_IGNORE_CASE;
		else if ((*args)[1] == 'f')
			patflags |= ACL_PAT_F_FROM_FILE;
		else if ((*args)[1] == '-') {
			args++;
			break;
		}
		else
			break;
		args++;
	}

	/* now parse all patterns */
	opaque = 0;
	while (**args) {
		int ret;
		pattern = (struct acl_pattern *)calloc(1, sizeof(*pattern));
		if (!pattern)
			goto out_free_expr;
		pattern->flags = patflags;

		ret = aclkw->parse(args, pattern, &opaque);
		if (!ret)
			goto out_free_pattern;
		LIST_ADDQ(&expr->patterns, &pattern->list);
		args += ret;
	}

	return expr;

 out_free_pattern:
	free_pattern(pattern);
 out_free_expr:
	prune_acl_expr(expr);
	free(expr);
 out_return:
	return NULL;
}

/* Parse an ACL with the name starting at <args>[0], and with a list of already
 * known ACLs in <acl>. If the ACL was not in the list, it will be added.
 * A pointer to that ACL is returned.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;

	acl_expr = parse_acl_expr(args + 1);
	if (!acl_expr)
		goto out_return;

	cur_acl = find_acl_by_name(args[0], known_acl);
	if (!cur_acl) {
		name = strdup(args[0]);
		if (!name)
			goto out_free_acl_expr;
		cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
		if (cur_acl == NULL)
			goto out_free_name;

		LIST_INIT(&cur_acl->expr);
		LIST_ADDQ(known_acl, &cur_acl->list);
		cur_acl->name = name;
	}

	LIST_ADDQ(&cur_acl->expr, &acl_expr->list);
	return cur_acl;

 out_free_name:
	free(name);
 out_free_acl_expr:
	prune_acl_expr(acl_expr);
	free(acl_expr);
 out_return:
	return NULL;
}

/* Some useful ACLs provided by default. Only those used are allocated. */

const struct {
	const char *name;
	const char *expr[4]; /* put enough for longest expression */
} default_acl_list[] = {
	{ .name = "LOCALHOST",      .expr = {"src","127.0.0.1/8",""}},
	{ .name = "HTTP_1.0",       .expr = {"req_ver","1.0",""}},
	{ .name = "HTTP_1.1",       .expr = {"req_ver","1.1",""}},
	{ .name = "METH_CONNECT",   .expr = {"method","CONNECT",""}},
	{ .name = "METH_GET",       .expr = {"method","GET","HEAD",""}},
	{ .name = "METH_HEAD",      .expr = {"method","HEAD",""}},
	{ .name = "METH_OPTIONS",   .expr = {"method","OPTIONS",""}},
	{ .name = "METH_POST",      .expr = {"method","POST",""}},
	{ .name = "METH_TRACE",     .expr = {"method","TRACE",""}},
	{ .name = "HTTP_URL_ABS",   .expr = {"url_reg","^[^/:]*://",""}},
	{ .name = "HTTP_URL_SLASH", .expr = {"url_beg","/",""}},
	{ .name = "HTTP_URL_STAR",  .expr = {"url","*",""}},
	{ .name = "HTTP_CONTENT",   .expr = {"hdr_val(content-length)","gt","0",""}},
	{ .name = NULL, .expr = {""}}
};

/* Find a default ACL from the default_acl list, compile it and return it.
 * If the ACL is not found, NULL is returned. In theory, it cannot fail,
 * except when default ACLs are broken, in which case it will return NULL.
 * If <known_acl> is not NULL, the ACL will be queued at its tail.
 */
struct acl *find_acl_default(const char *acl_name, struct list *known_acl)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;
	int index;

	for (index = 0; default_acl_list[index].name != NULL; index++) {
		if (strcmp(acl_name, default_acl_list[index].name) == 0)
			break;
	}

	if (default_acl_list[index].name == NULL)
		return NULL;

	acl_expr = parse_acl_expr((const char **)default_acl_list[index].expr);
	if (!acl_expr)
		goto out_return;

	name = strdup(acl_name);
	if (!name)
		goto out_free_acl_expr;
	cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
	if (cur_acl == NULL)
		goto out_free_name;

	cur_acl->name = name;
	LIST_INIT(&cur_acl->expr);
	LIST_ADDQ(&cur_acl->expr, &acl_expr->list);
	if (known_acl)
		LIST_ADDQ(known_acl, &cur_acl->list);

	return cur_acl;

 out_free_name:
	free(name);
 out_free_acl_expr:
	prune_acl_expr(acl_expr);
	free(acl_expr);
 out_return:
	return NULL;
}

/* Purge everything in the acl_cond <cond>, then return <cond>. */
struct acl_cond *prune_acl_cond(struct acl_cond *cond)
{
	struct acl_term_suite *suite, *tmp_suite;
	struct acl_term *term, *tmp_term;

	/* iterate through all term suites and free all terms and all suites */
	list_for_each_entry_safe(suite, tmp_suite, &cond->suites, list) {
		list_for_each_entry_safe(term, tmp_term, &suite->terms, list)
			free(term);
		free(suite);
	}
	return cond;
}

/* Parse an ACL condition starting at <args>[0], relying on a list of already
 * known ACLs passed in <known_acl>. The new condition is returned (or NULL in
 * case of low memory). Supports multiple conditions separated by "or".
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl, int pol)
{
	__label__ out_return, out_free_suite, out_free_term;
	int arg, neg;
	const char *word;
	struct acl *cur_acl;
	struct acl_term *cur_term;
	struct acl_term_suite *cur_suite;
	struct acl_cond *cond;

	cond = (struct acl_cond *)calloc(1, sizeof(*cond));
	if (cond == NULL)
		goto out_return;

	LIST_INIT(&cond->list);
	LIST_INIT(&cond->suites);
	cond->pol = pol;

	cur_suite = NULL;
	neg = 0;
	for (arg = 0; *args[arg]; arg++) {
		word = args[arg];

		/* remove as many exclamation marks as we can */
		while (*word == '!') {
			neg = !neg;
			word++;
		}

		/* an empty word is allowed because we cannot force the user to
		 * always think about not leaving exclamation marks alone.
		 */
		if (!*word)
			continue;

		if (strcasecmp(word, "or") == 0 || strcmp(word, "||") == 0) {
			/* new term suite */
			cur_suite = NULL;
			neg = 0;
			continue;
		}

		/* search for <word> in the known ACL names. If we do not find
		 * it, let's look for it in the default ACLs, and if found, add
		 * it to the list of ACLs of this proxy. This makes it possible
		 * to override them.
		 */
		cur_acl = find_acl_by_name(word, known_acl);
		if (cur_acl == NULL) {
			cur_acl = find_acl_default(word, known_acl);
			if (cur_acl == NULL)
				goto out_free_suite;
		}

		cur_term = (struct acl_term *)calloc(1, sizeof(*cur_term));
		if (cur_term == NULL)
			goto out_free_suite;

		cur_term->acl = cur_acl;
		cur_term->neg = neg;

		if (!cur_suite) {
			cur_suite = (struct acl_term_suite *)calloc(1, sizeof(*cur_suite));
			if (cur_term == NULL)
				goto out_free_term;
			LIST_INIT(&cur_suite->terms);
			LIST_ADDQ(&cond->suites, &cur_suite->list);
		}
		LIST_ADDQ(&cur_suite->terms, &cur_term->list);
		neg = 0;
	}

	return cond;

 out_free_term:
	free(cur_term);
 out_free_suite:
	prune_acl_cond(cond);
	free(cond);
 out_return:
	return NULL;
}

/* Execute condition <cond> and return 0 if test fails or 1 if test succeeds.
 * This function only computes the condition, it does not apply the polarity
 * required by IF/UNLESS, it's up to the caller to do this.
 */
int acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *l4, void *l7, int dir)
{
	__label__ fetch_next;
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl_expr *expr;
	struct acl *acl;
	struct acl_pattern *pattern;
	struct acl_test test;
	int acl_res, pat_res, suite_res, cond_res;

	/* we're doing a logical OR between conditions so we initialize to FAIL */
	cond_res = ACL_PAT_FAIL;
	list_for_each_entry(suite, &cond->suites, list) {
		/* evaluate condition suite <suite>. We stop at the first term
		 * which does not return ACL_PAT_PASS.
		 */

		/* we're doing a logical AND between terms, so we must set the
		 * initial value to PASS.
		 */
		suite_res = ACL_PAT_PASS;
		list_for_each_entry(term, &suite->terms, list) {
			acl = term->acl;

			/* FIXME: use cache !
			 * check acl->cache_idx for this.
			 */

			/* ACL result not cached. Let's scan all the expressions
			 * and use the first one to match.
			 */
			acl_res = ACL_PAT_FAIL;
			list_for_each_entry(expr, &acl->expr, list) {
				/* we need to reset context and flags */
				memset(&test, 0, sizeof(test));
			fetch_next:
				if (!expr->kw->fetch(px, l4, l7, dir, expr, &test))
					continue;

				/* apply all tests to this value */
				list_for_each_entry(pattern, &expr->patterns, list) {
					pat_res = expr->kw->match(&test, pattern);

					if (pat_res & ACL_PAT_MISS) {
						/* there is at least one test which might be worth retrying later. */
						acl_res |= ACL_PAT_MISS;
						continue;
					} else if (pat_res & ACL_PAT_PASS) {
						/* we found one ! */
						acl_res |= ACL_PAT_PASS;
						break;
					}
				}
				/*
				 * OK now we have the result of this expression in acl_res.
				 *  - we have the PASS bit set if at least one pattern matched ;
				 *  - we have the MISS bit set if at least one pattern may match
				 *    later so that we should not cache a failure ;
				 *
				 * Then if (PASS || !MISS) we can cache the result, and put
				 * (test.flags & ACL_TEST_F_VOLATILE) in the cache flags.
				 *
				 * FIXME: implement cache.
				 *
				 */

				/* now we may have some cleanup to do */
				if (test.flags & ACL_TEST_F_MUST_FREE) {
					free(test.ptr);
					test.len = 0;
				}

				if (acl_res & ACL_PAT_PASS)
					break;

				/* prepare to test another expression */
				acl_res = ACL_PAT_FAIL;

				if (test.flags & ACL_TEST_F_FETCH_MORE)
					goto fetch_next;
			}
			/*
			 * Here we have the result of an ACL (cached or not).
			 * ACLs are combined, negated or not, to form conditions.
			 */

			acl_res &= ACL_PAT_PASS;
			if (term->neg)
				acl_res ^= ACL_PAT_PASS;

			suite_res &= acl_res;
			if (!(suite_res & ACL_PAT_PASS))
				break;
		}
		cond_res |= suite_res;
		if (cond_res & ACL_PAT_PASS)
			break;
	}

	return (cond_res & ACL_PAT_PASS) ? 1 : 0;
}


/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
#if 0
	{ "time",       acl_parse_time,  acl_fetch_time,   acl_match_time  },
#endif
	{ NULL, NULL, NULL, NULL }
}};


__attribute__((constructor))
static void __acl_init(void)
{
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
