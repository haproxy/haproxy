/*
 * ACL management functions.
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
#include <string.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/uri_auth.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/channel.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stick_table.h>

#include <ebsttree.h>

/* List head of all known ACL keywords */
static struct acl_kw_list acl_keywords = {
	.list = LIST_HEAD_INIT(acl_keywords.list)
};

/* input values are 0 or 3, output is the same */
static inline enum acl_test_res pat2acl(enum pat_match_res res)
{
	return (enum acl_test_res)res;
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
 * <kw> contains an opening parenthesis or a comma, only the left part of it is
 * checked.
 */
struct acl_keyword *find_acl_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct acl_kw_list *kwl;

	kwend = kw;
	while (*kwend && *kwend != '(' && *kwend != ',')
		kwend++;

	list_for_each_entry(kwl, &acl_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0)
				return &kwl->kw[index];
		}
	}
	return NULL;
}

static struct acl_expr *prune_acl_expr(struct acl_expr *expr)
{
	struct arg *arg;

	pattern_prune_expr(&expr->pat);

	for (arg = expr->smp->arg_p; arg; arg++) {
		if (arg->type == ARGT_STOP)
			break;
		if (arg->type == ARGT_STR || arg->unresolved) {
			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
		}
	}

	if (expr->smp->arg_p != empty_arg_list)
		free(expr->smp->arg_p);
	return expr;
}

/* Parse an ACL expression starting at <args>[0], and return it. If <err> is
 * not NULL, it will be filled with a pointer to an error message in case of
 * error. This pointer must be freeable or NULL. <al> is an arg_list serving
 * as a list head to report missing dependencies.
 *
 * Right now, the only accepted syntax is :
 * <subject> [<value>...]
 */
struct acl_expr *parse_acl_expr(const char **args, char **err, struct arg_list *al)
{
	__label__ out_return, out_free_expr, out_free_pattern;
	struct acl_expr *expr;
	struct acl_keyword *aclkw;
	struct pattern *pattern;
	int patflags;
	const char *arg;
	struct sample_expr *smp = NULL;
	int idx = 0;
	char *ckw = NULL;
	const char *begw;
	const char *endw;
	const char *endt;
	unsigned long prev_type;
	int cur_type;
	int nbargs;

	/* First, we look for an ACL keyword. And if we don't find one, then
	 * we look for a sample fetch expression starting with a sample fetch
	 * keyword.
	 */

	al->ctx  = ARGC_ACL;   // to report errors while resolving args late
	al->kw   = *args;
	al->conv = NULL;

	aclkw = find_acl_kw(args[0]);
	if (aclkw && aclkw->parse) {
		/* OK we have a real ACL keyword */

		/* build new sample expression for this ACL */
		smp = calloc(1, sizeof(struct sample_expr));
		if (!smp) {
			memprintf(err, "out of memory when parsing ACL expression");
			goto out_return;
		}
		LIST_INIT(&(smp->conv_exprs));
		smp->fetch = aclkw->smp;
		smp->arg_p = empty_arg_list;

		/* look for the begining of the subject arguments */
		for (arg = args[0]; *arg && *arg != '(' && *arg != ','; arg++);

		endt = arg;
		if (*endt == '(') {
			/* look for the end of this term and skip the opening parenthesis */
			endt = ++arg;
			while (*endt && *endt != ')')
				endt++;
			if (*endt != ')') {
				memprintf(err, "missing closing ')' after arguments to ACL keyword '%s'", aclkw->kw);
				goto out_free_smp;
			}
		}

		/* At this point, we have :
		 *   - args[0] : beginning of the keyword
		 *   - arg     : end of the keyword, first character not part of keyword
		 *               nor the opening parenthesis (so first character of args
		 *               if present).
		 *   - endt    : end of the term (=arg or last parenthesis if args are present)
		 */
		nbargs = make_arg_list(arg, endt - arg, smp->fetch->arg_mask, &smp->arg_p,
		                       err, NULL, NULL, al);
		if (nbargs < 0) {
			/* note that make_arg_list will have set <err> here */
			memprintf(err, "ACL keyword '%s' : %s", aclkw->kw, *err);
			goto out_free_smp;
		}

		if (!smp->arg_p) {
			smp->arg_p = empty_arg_list;
		}
		else if (smp->fetch->val_args && !smp->fetch->val_args(smp->arg_p, err)) {
			/* invalid keyword argument, error must have been
			 * set by val_args().
			 */
			memprintf(err, "in argument to '%s', %s", aclkw->kw, *err);
			goto out_free_smp;
		}
		arg = endt;

		/* look for the begining of the converters list. Those directly attached
		 * to the ACL keyword are found just after <arg> which points to the comma.
		 */
		prev_type = smp->fetch->out_type;
		while (*arg) {
			struct sample_conv *conv;
			struct sample_conv_expr *conv_expr;

			if (*arg == ')') /* skip last closing parenthesis */
				arg++;

			if (*arg && *arg != ',') {
				if (ckw)
					memprintf(err, "ACL keyword '%s' : missing comma after conv keyword '%s'.",
						  aclkw->kw, ckw);
				else
					memprintf(err, "ACL keyword '%s' : missing comma after fetch keyword.",
						  aclkw->kw);
				goto out_free_smp;
			}

			while (*arg == ',') /* then trailing commas */
				arg++;

			begw = arg; /* start of conv keyword */

			if (!*begw)
				/* none ? end of converters */
				break;

			for (endw = begw; *endw && *endw != '(' && *endw != ','; endw++);

			free(ckw);
			ckw = my_strndup(begw, endw - begw);

			conv = find_sample_conv(begw, endw - begw);
			if (!conv) {
				/* Unknown converter method */
				memprintf(err, "ACL keyword '%s' : unknown conv method '%s'.",
					  aclkw->kw, ckw);
				goto out_free_smp;
			}

			arg = endw;
			if (*arg == '(') {
				/* look for the end of this term */
				while (*arg && *arg != ')')
					arg++;
				if (*arg != ')') {
					memprintf(err, "ACL keyword '%s' : syntax error: missing ')' after conv keyword '%s'.",
						  aclkw->kw, ckw);
					goto out_free_smp;
				}
			}

			if (conv->in_type >= SMP_TYPES || conv->out_type >= SMP_TYPES) {
				memprintf(err, "ACL keyword '%s' : returns type of conv method '%s' is unknown.",
					  aclkw->kw, ckw);
				goto out_free_smp;
			}

			/* If impossible type conversion */
			if (!sample_casts[prev_type][conv->in_type]) {
				memprintf(err, "ACL keyword '%s' : conv method '%s' cannot be applied.",
					  aclkw->kw, ckw);
				goto out_free_smp;
			}

			prev_type = conv->out_type;
			conv_expr = calloc(1, sizeof(struct sample_conv_expr));
			if (!conv_expr)
				goto out_free_smp;

			LIST_ADDQ(&(smp->conv_exprs), &(conv_expr->list));
			conv_expr->conv = conv;

			if (arg != endw) {
				int err_arg;

				if (!conv->arg_mask) {
					memprintf(err, "ACL keyword '%s' : conv method '%s' does not support any args.",
						  aclkw->kw, ckw);
					goto out_free_smp;
				}

				al->kw = smp->fetch->kw;
				al->conv = conv_expr->conv->kw;
				if (make_arg_list(endw + 1, arg - endw - 1, conv->arg_mask, &conv_expr->arg_p, err, NULL, &err_arg, al) < 0) {
					memprintf(err, "ACL keyword '%s' : invalid arg %d in conv method '%s' : %s.",
						  aclkw->kw, err_arg+1, ckw, *err);
					goto out_free_smp;
				}

				if (!conv_expr->arg_p)
					conv_expr->arg_p = empty_arg_list;

				if (conv->val_args && !conv->val_args(conv_expr->arg_p, conv, err)) {
					memprintf(err, "ACL keyword '%s' : invalid args in conv method '%s' : %s.",
						  aclkw->kw, ckw, *err);
					goto out_free_smp;
				}
			}
			else if (ARGM(conv->arg_mask)) {
				memprintf(err, "ACL keyword '%s' : missing args for conv method '%s'.",
					  aclkw->kw, ckw);
				goto out_free_smp;
			}
		}
	}
	else {
		/* This is not an ACL keyword, so we hope this is a sample fetch
		 * keyword that we're going to transparently use as an ACL. If
		 * so, we retrieve a completely parsed expression with args and
		 * convs already done.
		 */
		smp = sample_parse_expr((char **)args, &idx, err, al);
		if (!smp) {
			memprintf(err, "%s in ACL expression '%s'", *err, *args);
			goto out_return;
		}
	}

	expr = (struct acl_expr *)calloc(1, sizeof(*expr));
	if (!expr) {
		memprintf(err, "out of memory when parsing ACL expression");
		goto out_return;
	}

	pattern_init_expr(&expr->pat);

	expr->kw = aclkw ? aclkw->kw : smp->fetch->kw;
	expr->pat.parse = aclkw ? aclkw->parse : NULL;
	expr->pat.match = aclkw ? aclkw->match : NULL;
	expr->smp = smp;
	smp = NULL;

	if (!expr->pat.parse) {
		/* some types can be automatically converted */

		switch (expr->smp ? expr->smp->fetch->out_type : aclkw->smp->out_type) {
		case SMP_T_BOOL:
			expr->pat.parse = pat_parse_fcts[PAT_MATCH_BOOL];
			expr->pat.match = pat_match_fcts[PAT_MATCH_BOOL];
			break;
		case SMP_T_SINT:
		case SMP_T_UINT:
			expr->pat.parse = pat_parse_fcts[PAT_MATCH_INT];
			expr->pat.match = pat_match_fcts[PAT_MATCH_INT];
			break;
		case SMP_T_IPV4:
		case SMP_T_IPV6:
			expr->pat.parse = pat_parse_fcts[PAT_MATCH_IP];
			expr->pat.match = pat_match_fcts[PAT_MATCH_IP];
			break;
		}
	}

	/* Additional check to protect against common mistakes */
	cur_type = smp_expr_output_type(expr->smp);
	if (expr->pat.parse && cur_type != SMP_T_BOOL && !*args[1]) {
		Warning("parsing acl keyword '%s' :\n"
		        "  no pattern to match against were provided, so this ACL will never match.\n"
		        "  If this is what you intended, please add '--' to get rid of this warning.\n"
		        "  If you intended to match only for existence, please use '-m found'.\n"
		        "  If you wanted to force an int to match as a bool, please use '-m bool'.\n"
		        "\n",
		        args[0]);
	}

	args++;

	/* check for options before patterns. Supported options are :
	 *   -i : ignore case for all patterns by default
	 *   -f : read patterns from those files
	 *   -m : force matching method (must be used before -f)
	 *   -- : everything after this is not an option
	 */
	patflags = 0;
	while (**args == '-') {
		if ((*args)[1] == 'i')
			patflags |= PAT_F_IGNORE_CASE;
		else if ((*args)[1] == 'f') {
			if (!expr->pat.parse) {
				memprintf(err, "matching method must be specified first (using '-m') when using a sample fetch of this type ('%s')", expr->kw);
				goto out_free_expr;
			}

			if (!pattern_read_from_file(&expr->pat, args[1], patflags | PAT_F_FROM_FILE, err))
				goto out_free_expr;
			args++;
		}
		else if ((*args)[1] == 'm') {
			int idx;

			if (!LIST_ISEMPTY(&expr->pat.patterns) || !eb_is_empty(&expr->pat.pattern_tree)) {
				memprintf(err, "'-m' must only be specified before patterns and files in parsing ACL expression");
				goto out_free_expr;
			}

			idx = pat_find_match_name(args[1]);
			if (idx < 0) {
				memprintf(err, "unknown matching method '%s' when parsing ACL expression", args[1]);
				goto out_free_expr;
			}

			/* Note: -m found is always valid, bool/int are compatible, str/bin/reg/len are compatible */
			if (!sample_casts[cur_type][pat_match_types[idx]]) {
				memprintf(err, "matching method '%s' cannot be used with fetch keyword '%s'", args[1], expr->kw);
				goto out_free_expr;
			}
			expr->pat.parse = pat_parse_fcts[idx];
			expr->pat.match = pat_match_fcts[idx];
			args++;
		}
		else if ((*args)[1] == '-') {
			args++;
			break;
		}
		else
			break;
		args++;
	}

	if (!expr->pat.parse) {
		memprintf(err, "matching method must be specified first (using '-m') when using a sample fetch of this type ('%s')", expr->kw);
		goto out_free_expr;
	}

	/* now parse all patterns */
	pattern = NULL;
	if (!pattern_register(&expr->pat, args, NULL, &pattern, patflags, err))
		goto out_free_pattern;

	return expr;

 out_free_pattern:
	pattern_free(pattern);
 out_free_expr:
	prune_acl_expr(expr);
	free(expr);
	free(ckw);
 out_free_smp:
	free(smp);
 out_return:
	return NULL;
}

/* Purge everything in the acl <acl>, then return <acl>. */
struct acl *prune_acl(struct acl *acl) {

	struct acl_expr *expr, *exprb;

	free(acl->name);

	list_for_each_entry_safe(expr, exprb, &acl->expr, list) {
		LIST_DEL(&expr->list);
		prune_acl_expr(expr);
		free(expr);
	}

	return acl;
}

/* Parse an ACL with the name starting at <args>[0], and with a list of already
 * known ACLs in <acl>. If the ACL was not in the list, it will be added.
 * A pointer to that ACL is returned. If the ACL has an empty name, then it's
 * an anonymous one and it won't be merged with any other one. If <err> is not
 * NULL, it will be filled with an appropriate error. This pointer must be
 * freeable or NULL. <al> is the arg_list serving as a head for unresolved
 * dependencies.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl, char **err, struct arg_list *al)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;
	const char *pos;

	if (**args && (pos = invalid_char(*args))) {
		memprintf(err, "invalid character in ACL name : '%c'", *pos);
		goto out_return;
	}

	acl_expr = parse_acl_expr(args + 1, err, al);
	if (!acl_expr) {
		/* parse_acl_expr will have filled <err> here */
		goto out_return;
	}

	/* Check for args beginning with an opening parenthesis just after the
	 * subject, as this is almost certainly a typo. Right now we can only
	 * emit a warning, so let's do so.
	 */
	if (!strchr(args[1], '(') && *args[2] == '(')
		Warning("parsing acl '%s' :\n"
			"  matching '%s' for pattern '%s' is likely a mistake and probably\n"
			"  not what you want. Maybe you need to remove the extraneous space before '('.\n"
			"  If you are really sure this is not an error, please insert '--' between the\n"
			"  match and the pattern to make this warning message disappear.\n",
			args[0], args[1], args[2]);

	if (*args[0])
		cur_acl = find_acl_by_name(args[0], known_acl);
	else
		cur_acl = NULL;

	if (!cur_acl) {
		name = strdup(args[0]);
		if (!name) {
			memprintf(err, "out of memory when parsing ACL");
			goto out_free_acl_expr;
		}
		cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
		if (cur_acl == NULL) {
			memprintf(err, "out of memory when parsing ACL");
			goto out_free_name;
		}

		LIST_INIT(&cur_acl->expr);
		LIST_ADDQ(known_acl, &cur_acl->list);
		cur_acl->name = name;
	}

	/* We want to know what features the ACL needs (typically HTTP parsing),
	 * and where it may be used. If an ACL relies on multiple matches, it is
	 * OK if at least one of them may match in the context where it is used.
	 */
	cur_acl->use |= acl_expr->smp->fetch->use;
	cur_acl->val |= acl_expr->smp->fetch->val;
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
	{ .name = "TRUE",           .expr = {"always_true",""}},
	{ .name = "FALSE",          .expr = {"always_false",""}},
	{ .name = "LOCALHOST",      .expr = {"src","127.0.0.1/8",""}},
	{ .name = "HTTP",           .expr = {"req_proto_http",""}},
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
	{ .name = "RDP_COOKIE",     .expr = {"req_rdp_cookie_cnt","gt","0",""}},
	{ .name = "REQ_CONTENT",    .expr = {"req_len","gt","0",""}},
	{ .name = "WAIT_END",       .expr = {"wait_end",""}},
	{ .name = NULL, .expr = {""}}
};

/* Find a default ACL from the default_acl list, compile it and return it.
 * If the ACL is not found, NULL is returned. In theory, it cannot fail,
 * except when default ACLs are broken, in which case it will return NULL.
 * If <known_acl> is not NULL, the ACL will be queued at its tail. If <err> is
 * not NULL, it will be filled with an error message if an error occurs. This
 * pointer must be freeable or NULL. <al> is an arg_list serving as a list head
 * to report missing dependencies.
 */
static struct acl *find_acl_default(const char *acl_name, struct list *known_acl,
                                    char **err, struct arg_list *al)
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

	if (default_acl_list[index].name == NULL) {
		memprintf(err, "no such ACL : '%s'", acl_name);
		return NULL;
	}

	acl_expr = parse_acl_expr((const char **)default_acl_list[index].expr, err, al);
	if (!acl_expr) {
		/* parse_acl_expr must have filled err here */
		goto out_return;
	}

	name = strdup(acl_name);
	if (!name) {
		memprintf(err, "out of memory when building default ACL '%s'", acl_name);
		goto out_free_acl_expr;
	}

	cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
	if (cur_acl == NULL) {
		memprintf(err, "out of memory when building default ACL '%s'", acl_name);
		goto out_free_name;
	}

	cur_acl->name = name;
	cur_acl->use |= acl_expr->smp->fetch->use;
	cur_acl->val |= acl_expr->smp->fetch->val;
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
 * case of low memory). Supports multiple conditions separated by "or". If
 * <err> is not NULL, it will be filled with a pointer to an error message in
 * case of error, that the caller is responsible for freeing. The initial
 * location must either be freeable or NULL. The list <al> serves as a list head
 * for unresolved dependencies.
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl,
                                enum acl_cond_pol pol, char **err, struct arg_list *al)
{
	__label__ out_return, out_free_suite, out_free_term;
	int arg, neg;
	const char *word;
	struct acl *cur_acl;
	struct acl_term *cur_term;
	struct acl_term_suite *cur_suite;
	struct acl_cond *cond;
	unsigned int suite_val;

	cond = (struct acl_cond *)calloc(1, sizeof(*cond));
	if (cond == NULL) {
		memprintf(err, "out of memory when parsing condition");
		goto out_return;
	}

	LIST_INIT(&cond->list);
	LIST_INIT(&cond->suites);
	cond->pol = pol;
	cond->val = 0;

	cur_suite = NULL;
	suite_val = ~0U;
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
			cond->val |= suite_val;
			suite_val = ~0U;
			cur_suite = NULL;
			neg = 0;
			continue;
		}

		if (strcmp(word, "{") == 0) {
			/* we may have a complete ACL expression between two braces,
			 * find the last one.
			 */
			int arg_end = arg + 1;
			const char **args_new;

			while (*args[arg_end] && strcmp(args[arg_end], "}") != 0)
				arg_end++;

			if (!*args[arg_end]) {
				memprintf(err, "missing closing '}' in condition");
				goto out_free_suite;
			}

			args_new = calloc(1, (arg_end - arg + 1) * sizeof(*args_new));
			if (!args_new) {
				memprintf(err, "out of memory when parsing condition");
				goto out_free_suite;
			}

			args_new[0] = "";
			memcpy(args_new + 1, args + arg + 1, (arg_end - arg) * sizeof(*args_new));
			args_new[arg_end - arg] = "";
			cur_acl = parse_acl(args_new, known_acl, err, al);
			free(args_new);

			if (!cur_acl) {
				/* note that parse_acl() must have filled <err> here */
				goto out_free_suite;
			}
			word = args[arg + 1];
			arg = arg_end;
		}
		else {
			/* search for <word> in the known ACL names. If we do not find
			 * it, let's look for it in the default ACLs, and if found, add
			 * it to the list of ACLs of this proxy. This makes it possible
			 * to override them.
			 */
			cur_acl = find_acl_by_name(word, known_acl);
			if (cur_acl == NULL) {
				cur_acl = find_acl_default(word, known_acl, err, al);
				if (cur_acl == NULL) {
					/* note that find_acl_default() must have filled <err> here */
					goto out_free_suite;
				}
			}
		}

		cur_term = (struct acl_term *)calloc(1, sizeof(*cur_term));
		if (cur_term == NULL) {
			memprintf(err, "out of memory when parsing condition");
			goto out_free_suite;
		}

		cur_term->acl = cur_acl;
		cur_term->neg = neg;

		/* Here it is a bit complex. The acl_term_suite is a conjunction
		 * of many terms. It may only be used if all of its terms are
		 * usable at the same time. So the suite's validity domain is an
		 * AND between all ACL keywords' ones. But, the global condition
		 * is valid if at least one term suite is OK. So it's an OR between
		 * all of their validity domains. We could emit a warning as soon
		 * as suite_val is null because it means that the last ACL is not
		 * compatible with the previous ones. Let's remain simple for now.
		 */
		cond->use |= cur_acl->use;
		suite_val &= cur_acl->val;

		if (!cur_suite) {
			cur_suite = (struct acl_term_suite *)calloc(1, sizeof(*cur_suite));
			if (cur_suite == NULL) {
				memprintf(err, "out of memory when parsing condition");
				goto out_free_term;
			}
			LIST_INIT(&cur_suite->terms);
			LIST_ADDQ(&cond->suites, &cur_suite->list);
		}
		LIST_ADDQ(&cur_suite->terms, &cur_term->list);
		neg = 0;
	}

	cond->val |= suite_val;
	return cond;

 out_free_term:
	free(cur_term);
 out_free_suite:
	prune_acl_cond(cond);
	free(cond);
 out_return:
	return NULL;
}

/* Builds an ACL condition starting at the if/unless keyword. The complete
 * condition is returned. NULL is returned in case of error or if the first
 * word is neither "if" nor "unless". It automatically sets the file name and
 * the line number in the condition for better error reporting, and sets the
 * HTTP intiailization requirements in the proxy. If <err> is not NULL, it will
 * be filled with a pointer to an error message in case of error, that the
 * caller is responsible for freeing. The initial location must either be
 * freeable or NULL.
 */
struct acl_cond *build_acl_cond(const char *file, int line, struct proxy *px, const char **args, char **err)
{
	enum acl_cond_pol pol = ACL_COND_NONE;
	struct acl_cond *cond = NULL;

	if (err)
		*err = NULL;

	if (!strcmp(*args, "if")) {
		pol = ACL_COND_IF;
		args++;
	}
	else if (!strcmp(*args, "unless")) {
		pol = ACL_COND_UNLESS;
		args++;
	}
	else {
		memprintf(err, "conditions must start with either 'if' or 'unless'");
		return NULL;
	}

	cond = parse_acl_cond(args, &px->acl, pol, err, &px->conf.args);
	if (!cond) {
		/* note that parse_acl_cond must have filled <err> here */
		return NULL;
	}

	cond->file = file;
	cond->line = line;
	px->http_needed |= !!(cond->use & SMP_USE_HTTP_ANY);
	return cond;
}

/* Execute condition <cond> and return either ACL_TEST_FAIL, ACL_TEST_MISS or
 * ACL_TEST_PASS depending on the test results. ACL_TEST_MISS may only be
 * returned if <opt> does not contain SMP_OPT_FINAL, indicating that incomplete
 * data is being examined. The function automatically sets SMP_OPT_ITERATE. This
 * function only computes the condition, it does not apply the polarity required
 * by IF/UNLESS, it's up to the caller to do this using something like this :
 *
 *     res = acl_pass(res);
 *     if (res == ACL_TEST_MISS)
 *         return 0;
 *     if (cond->pol == ACL_COND_UNLESS)
 *         res = !res;
 */
enum acl_test_res acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *l4, void *l7, unsigned int opt)
{
	__label__ fetch_next;
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl_expr *expr;
	struct acl *acl;
	struct sample smp;
	enum acl_test_res acl_res, suite_res, cond_res;

	/* ACLs are iterated over all values, so let's always set the flag to
	 * indicate this to the fetch functions.
	 */
	opt |= SMP_OPT_ITERATE;

	/* We're doing a logical OR between conditions so we initialize to FAIL.
	 * The MISS status is propagated down from the suites.
	 */
	cond_res = ACL_TEST_FAIL;
	list_for_each_entry(suite, &cond->suites, list) {
		/* Evaluate condition suite <suite>. We stop at the first term
		 * which returns ACL_TEST_FAIL. The MISS status is still propagated
		 * in case of uncertainty in the result.
		 */

		/* we're doing a logical AND between terms, so we must set the
		 * initial value to PASS.
		 */
		suite_res = ACL_TEST_PASS;
		list_for_each_entry(term, &suite->terms, list) {
			acl = term->acl;

			/* FIXME: use cache !
			 * check acl->cache_idx for this.
			 */

			/* ACL result not cached. Let's scan all the expressions
			 * and use the first one to match.
			 */
			acl_res = ACL_TEST_FAIL;
			list_for_each_entry(expr, &acl->expr, list) {
				/* we need to reset context and flags */
				memset(&smp, 0, sizeof(smp));
			fetch_next:
				if (!sample_process(px, l4, l7, opt, expr->smp, &smp)) {
					/* maybe we could not fetch because of missing data */
					if (smp.flags & SMP_F_MAY_CHANGE && !(opt & SMP_OPT_FINAL))
						acl_res |= ACL_TEST_MISS;
					continue;
				}

				acl_res |= pat2acl(pattern_exec_match(&expr->pat, &smp, NULL, NULL, NULL));
				/*
				 * OK now acl_res holds the result of this expression
				 * as one of ACL_TEST_FAIL, ACL_TEST_MISS or ACL_TEST_PASS.
				 *
				 * Then if (!MISS) we can cache the result, and put
				 * (smp.flags & SMP_F_VOLATILE) in the cache flags.
				 *
				 * FIXME: implement cache.
				 *
				 */

				/* we're ORing these terms, so a single PASS is enough */
				if (acl_res == ACL_TEST_PASS)
					break;

				if (smp.flags & SMP_F_NOT_LAST)
					goto fetch_next;

				/* sometimes we know the fetched data is subject to change
				 * later and give another chance for a new match (eg: request
				 * size, time, ...)
				 */
				if (smp.flags & SMP_F_MAY_CHANGE && !(opt & SMP_OPT_FINAL))
					acl_res |= ACL_TEST_MISS;
			}
			/*
			 * Here we have the result of an ACL (cached or not).
			 * ACLs are combined, negated or not, to form conditions.
			 */

			if (term->neg)
				acl_res = acl_neg(acl_res);

			suite_res &= acl_res;

			/* we're ANDing these terms, so a single FAIL or MISS is enough */
			if (suite_res != ACL_TEST_PASS)
				break;
		}
		cond_res |= suite_res;

		/* we're ORing these terms, so a single PASS is enough */
		if (cond_res == ACL_TEST_PASS)
			break;
	}
	return cond_res;
}

/* Returns a pointer to the first ACL conflicting with usage at place <where>
 * which is one of the SMP_VAL_* bits indicating a check place, or NULL if
 * no conflict is found. Only full conflicts are detected (ACL is not usable).
 * Use the next function to check for useless keywords.
 */
const struct acl *acl_cond_conflicts(const struct acl_cond *cond, unsigned int where)
{
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl *acl;

	list_for_each_entry(suite, &cond->suites, list) {
		list_for_each_entry(term, &suite->terms, list) {
			acl = term->acl;
			if (!(acl->val & where))
				return acl;
		}
	}
	return NULL;
}

/* Returns a pointer to the first ACL and its first keyword to conflict with
 * usage at place <where> which is one of the SMP_VAL_* bits indicating a check
 * place. Returns true if a conflict is found, with <acl> and <kw> set (if non
 * null), or false if not conflict is found. The first useless keyword is
 * returned.
 */
int acl_cond_kw_conflicts(const struct acl_cond *cond, unsigned int where, struct acl const **acl, char const **kw)
{
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl_expr *expr;

	list_for_each_entry(suite, &cond->suites, list) {
		list_for_each_entry(term, &suite->terms, list) {
			list_for_each_entry(expr, &term->acl->expr, list) {
				if (!(expr->smp->fetch->val & where)) {
					if (acl)
						*acl = term->acl;
					if (kw)
						*kw = expr->kw;
					return 1;
				}
			}
		}
	}
	return 0;
}

/*
 * Find targets for userlist and groups in acl. Function returns the number
 * of errors or OK if everything is fine. It must be called only once sample
 * fetch arguments have been resolved (after smp_resolve_args()).
 */
int acl_find_targets(struct proxy *p)
{

	struct acl *acl;
	struct acl_expr *expr;
	struct pattern *pattern;
	int cfgerr = 0;

	list_for_each_entry(acl, &p->acl, list) {
		list_for_each_entry(expr, &acl->expr, list) {
			if (!strcmp(expr->kw, "http_auth_group")) {
				/* Note: the ARGT_USR argument may only have been resolved earlier
				 * by smp_resolve_args().
				 */
				if (expr->smp->arg_p->unresolved) {
					Alert("Internal bug in proxy %s: %sacl %s %s() makes use of unresolved userlist '%s'. Please report this.\n",
					      p->id, *acl->name ? "" : "anonymous ", acl->name, expr->kw, expr->smp->arg_p->data.str.str);
					cfgerr++;
					continue;
				}

				if (LIST_ISEMPTY(&expr->pat.patterns)) {
					Alert("proxy %s: acl %s %s(): no groups specified.\n",
						p->id, acl->name, expr->kw);
					cfgerr++;
					continue;
				}

				list_for_each_entry(pattern, &expr->pat.patterns, list) {
					/* this keyword only has one argument */
					pattern->val.group_mask = auth_resolve_groups(expr->smp->arg_p->data.usr, pattern->ptr.str);

					if (!pattern->val.group_mask) {
						Alert("proxy %s: acl %s %s(): invalid group '%s'.\n",
						      p->id, acl->name, expr->kw, pattern->ptr.str);
						cfgerr++;
					}
					free(pattern->ptr.str);
					pattern->ptr.str = NULL;
					pattern->len = 0;
				}
			}
		}
	}

	return cfgerr;
}

/* initializes ACLs by resolving the sample fetch names they rely upon.
 * Returns 0 on success, otherwise an error.
 */
int init_acl()
{
	int err = 0;
	int index;
	const char *name;
	struct acl_kw_list *kwl;
	struct sample_fetch *smp;

	list_for_each_entry(kwl, &acl_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			name = kwl->kw[index].fetch_kw;
			if (!name)
				name = kwl->kw[index].kw;

			smp = find_sample_fetch(name, strlen(name));
			if (!smp) {
				Alert("Critical internal error: ACL keyword '%s' relies on sample fetch '%s' which was not registered!\n",
				      kwl->kw[index].kw, name);
				err++;
				continue;
			}
			kwl->kw[index].smp = smp;
		}
	}
	return err;
}

/************************************************************************/
/*      All supported sample and ACL keywords must be declared here.    */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
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
