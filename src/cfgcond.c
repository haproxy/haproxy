/*
 * Configuration condition preprocessor
 *
 * Copyright 2000-2021 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cfgcond.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

/* supported condition predicates */
const struct cond_pred_kw cond_predicates[] = {
	{ "defined",                 CFG_PRED_DEFINED,                ARG1(1, STR)         },
	{ "feature",                 CFG_PRED_FEATURE,                ARG1(1, STR)         },
	{ "streq",                   CFG_PRED_STREQ,                  ARG2(2, STR, STR)    },
	{ "strneq",                  CFG_PRED_STRNEQ,                 ARG2(2, STR, STR)    },
	{ "strstr",                  CFG_PRED_STRSTR,                 ARG2(2, STR, STR)    },
	{ "version_atleast",         CFG_PRED_VERSION_ATLEAST,        ARG1(1, STR)         },
	{ "version_before",          CFG_PRED_VERSION_BEFORE,         ARG1(1, STR)         },
	{ "openssl_version_atleast", CFG_PRED_OSSL_VERSION_ATLEAST,   ARG1(1, STR)         },
	{ "openssl_version_before",  CFG_PRED_OSSL_VERSION_BEFORE,    ARG1(1, STR)         },
	{ "ssllib_name_startswith",  CFG_PRED_SSLLIB_NAME_STARTSWITH, ARG1(1, STR)         },
	{ "enabled",                 CFG_PRED_ENABLED,                ARG1(1, STR)         },
	{ NULL, CFG_PRED_NONE, 0 }
};

/* looks up a cond predicate matching the keyword in <str>, possibly followed
 * by a parenthesis. Returns a pointer to it or NULL if not found.
 */
const struct cond_pred_kw *cfg_lookup_cond_pred(const char *str)
{
	const struct cond_pred_kw *ret;
	int len = strcspn(str, " (");

	for (ret = &cond_predicates[0]; ret->word; ret++) {
		if (len != strlen(ret->word))
			continue;
		if (strncmp(str, ret->word, len) != 0)
			continue;
		return ret;
	}
	return NULL;
}

/* Frees <term> and its args. NULL is supported and does nothing. */
void cfg_free_cond_term(struct cfg_cond_term *term)
{
	if (!term)
		return;

	if (term->type == CCTT_PAREN) {
		cfg_free_cond_expr(term->expr);
		term->expr = NULL;
	}

	free_args(term->args);
	free(term->args);
	free(term);
}

/* Parse an indirect input text as a possible config condition term.
 * Returns <0 on parsing error, 0 if the parser is desynchronized, or >0 on
 * success. <term> is allocated and filled with the parsed info, and <text>
 * is updated on success to point to the first unparsed character, or is left
 * untouched on failure. On success, the caller must free <term> using
 * cfg_free_cond_term(). An error will be set in <err> on error, and only
 * in this case. In this case the first bad character will be reported in
 * <errptr>. <maxdepth> corresponds to the maximum recursion depth permitted,
 * it is decremented on each recursive call and the parsing will fail one
 * reaching <= 0.
 */
int cfg_parse_cond_term(const char **text, struct cfg_cond_term **term, char **err, const char **errptr, int maxdepth)
{
	struct cfg_cond_term *t;
	const char *in = *text;
	const char *end_ptr;
	int err_arg;
	int nbargs;
	char *end;
	long val;

	while (*in == ' ' || *in == '\t')
		in++;

	if (!*in) /* empty term does not parse */
		return 0;

	*term = NULL;
	if (maxdepth <= 0)
		goto fail0;

	t = *term = calloc(1, sizeof(**term));
	if (!t) {
		memprintf(err, "memory allocation error while parsing conditional expression '%s'", *text);
		goto fail1;
	}

	t->type = CCTT_NONE;
	t->args = NULL;
	t->neg  = 0;

	/* !<term> negates the term. White spaces permitted */
	while (*in == '!') {
		t->neg = !t->neg;
		do { in++; } while (*in == ' ' || *in == '\t');
	}

	val = strtol(in, &end, 0);
	if (end != in) {
		t->type = val ? CCTT_TRUE : CCTT_FALSE;
		*text = end;
		return 1;
	}

	/* Try to parse '(' EXPR ')' */
	if (*in == '(') {
		int ret;

		t->type = CCTT_PAREN;
		t->args = NULL;

		do { in++; } while (*in == ' ' || *in == '\t');
		ret = cfg_parse_cond_expr(&in, &t->expr, err, errptr, maxdepth - 1);
		if (ret == -1)
			goto fail2;
		if (ret == 0)
			goto fail0;

		/* find the closing ')' */
		while (*in == ' ' || *in == '\t')
			in++;
		if (*in != ')') {
			memprintf(err, "expected ')' after conditional expression '%s'", *text);
			goto fail1;
		}
		do { in++; } while (*in == ' ' || *in == '\t');
		*text = in;
		return 1;
	}

	/* below we'll likely all make_arg_list() so we must return only via
	 * the <done> label which frees the arg list.
	 */
	t->pred = cfg_lookup_cond_pred(in);
	if (t->pred) {
		t->type = CCTT_PRED;
		nbargs = make_arg_list(in + strlen(t->pred->word), -1,
		                       t->pred->arg_mask, &t->args, err,
		                       &end_ptr, &err_arg, NULL);
		if (nbargs < 0) {
			memprintf(err, "%s in argument %d of predicate '%s' used in conditional expression", *err, err_arg, t->pred->word);
			if (errptr)
				*errptr = end_ptr;
			goto fail2;
		}
		*text = end_ptr;
		return 1;
	}

 fail0:
	memprintf(err, "unparsable conditional expression '%s'", *text);
 fail1:
	if (errptr)
		*errptr = *text;
 fail2:
	cfg_free_cond_term(*term);
	*term = NULL;
	return -1;
}

/* evaluate a "enabled" expression. Only a subset of options are matched. It
 * returns 1 if the option is enabled. 0 is returned is the option is not
 * enabled or if it is not recognized.
 */
static int cfg_eval_cond_enabled(const char *str)
{
	if (strcmp(str, "POLL") == 0)
		return !!(global.tune.options & GTUNE_USE_POLL);
	else if (strcmp(str, "EPOLL") == 0)
		return !!(global.tune.options & GTUNE_USE_EPOLL);
	else if (strcmp(str, "KQUEUE") == 0)
		return !!(global.tune.options & GTUNE_USE_EPOLL);
	else if (strcmp(str, "EVPORTS") == 0)
		return !!(global.tune.options & GTUNE_USE_EVPORTS);
	else if (strcmp(str, "SPLICE") == 0)
		return !!(global.tune.options & GTUNE_USE_SPLICE);
	else if (strcmp(str, "GETADDRINFO") == 0)
		return !!(global.tune.options & GTUNE_USE_GAI);
	else if (strcmp(str, "REUSEPORT") == 0)
		return !!(proto_tcpv4.flags & PROTO_F_REUSEPORT_SUPPORTED);
	else if (strcmp(str, "FAST-FORWARD") == 0)
		return !!(global.tune.options & GTUNE_USE_FAST_FWD);
	else if (strcmp(str, "SERVER-SSL-VERIFY-NONE") == 0)
		return !!(global.ssl_server_verify == SSL_SERVER_VERIFY_NONE);
	return 0;
}

/* evaluate a condition term on a .if/.elif line. The condition was already
 * parsed in <term>. Returns -1 on error (in which case err is filled with a
 * message, and only in this case), 0 if the condition is false, 1 if it's
 * true.
 */
int cfg_eval_cond_term(const struct cfg_cond_term *term, char **err)
{
	int ret = -1;

	if (term->type == CCTT_FALSE)
		ret = 0;
	else if (term->type == CCTT_TRUE)
		ret = 1;
	else if (term->type == CCTT_PRED) {
		/* here we know we have a valid predicate with valid arguments
		 * placed in term->args (which the caller will free).
		 */
		switch (term->pred->prd) {
		case CFG_PRED_DEFINED:  // checks if arg exists as an environment variable
			ret = getenv(term->args[0].data.str.area) != NULL;
			break;

		case CFG_PRED_FEATURE: { // checks if the arg matches an enabled feature
			const char *p;

			ret = 0; // assume feature not found
			for (p = build_features; (p = strstr(p, term->args[0].data.str.area)); p++) {
				if (p > build_features &&
				    (p[term->args[0].data.str.data] == ' ' ||
				     p[term->args[0].data.str.data] == 0)) {
					if (*(p-1) == '+') {       // e.g. "+OPENSSL"
						ret = 1;
						break;
					}
					else if (*(p-1) == '-') {  // e.g. "-OPENSSL"
						ret = 0;
						break;
					}
					/* it was a sub-word, let's restart from next place */
				}
			}
			break;
		}
		case CFG_PRED_STREQ:    // checks if the two arg are equal
			ret = strcmp(term->args[0].data.str.area, term->args[1].data.str.area) == 0;
			break;

		case CFG_PRED_STRNEQ:   // checks if the two arg are different
			ret = strcmp(term->args[0].data.str.area, term->args[1].data.str.area) != 0;
			break;

		case CFG_PRED_STRSTR:   // checks if the 2nd arg is found in the first one
			ret = strstr(term->args[0].data.str.area, term->args[1].data.str.area) != NULL;
			break;

		case CFG_PRED_VERSION_ATLEAST: // checks if the current version is at least this one
			ret = compare_current_version(term->args[0].data.str.area) <= 0;
			break;

		case CFG_PRED_VERSION_BEFORE:  // checks if the current version is older than this one
			ret = compare_current_version(term->args[0].data.str.area) > 0;
			break;

		case CFG_PRED_OSSL_VERSION_ATLEAST: { // checks if the current openssl version is at least this one
			int opensslret = openssl_compare_current_version(term->args[0].data.str.area);

			if (opensslret < -1) /* can't parse the string or no openssl available */
				ret = -1;
			else
				ret = opensslret <= 0;
			break;
		}
		case CFG_PRED_OSSL_VERSION_BEFORE: { // checks if the current openssl version is older than this one
			int opensslret = openssl_compare_current_version(term->args[0].data.str.area);

			if (opensslret < -1) /* can't parse the string or no openssl available */
				ret = -1;
			else
				ret = opensslret > 0;
			break;
		}
		case CFG_PRED_SSLLIB_NAME_STARTSWITH: { // checks if the current SSL library's name starts with a specified string (can be used to distinguish OpenSSL from LibreSSL or BoringSSL)
			ret = openssl_compare_current_name(term->args[0].data.str.area) == 0;
			break;
		}
		case CFG_PRED_ENABLED: { // checks if the arg matches on a subset of enabled options
			ret = cfg_eval_cond_enabled(term->args[0].data.str.area) != 0;
			break;
		}
		default:
			memprintf(err, "internal error: unhandled conditional expression predicate '%s'", term->pred->word);
			break;
		}
	}
	else if (term->type == CCTT_PAREN) {
		ret = cfg_eval_cond_expr(term->expr, err);
	}
	else {
		memprintf(err, "internal error: unhandled condition term type %d", (int)term->type);
	}

	if (ret >= 0 && term->neg)
		ret = !ret;
	return ret;
}


/* Frees <expr> and its terms and args. NULL is supported and does nothing. */
void cfg_free_cond_and(struct cfg_cond_and *expr)
{
	struct cfg_cond_and *prev;

	while (expr) {
		cfg_free_cond_term(expr->left);
		prev = expr;
		expr = expr->right;
		free(prev);
	}
}

/* Frees <expr> and its terms and args. NULL is supported and does nothing. */
void cfg_free_cond_expr(struct cfg_cond_expr *expr)
{
	struct cfg_cond_expr *prev;

	while (expr) {
		cfg_free_cond_and(expr->left);
		prev = expr;
		expr = expr->right;
		free(prev);
	}
}

/* Parse an indirect input text as a possible config condition sub-expr.
 * Returns <0 on parsing error, 0 if the parser is desynchronized, or >0 on
 * success. <expr> is filled with the parsed info, and <text> is updated on
 * success to point to the first unparsed character, or is left untouched
 * on failure. On success, the caller will have to free all lower-level
 * allocated structs using cfg_free_cond_expr(). An error will be set in
 * <err> on error, and only in this case. In this case the first bad
 * character will be reported in <errptr>. <maxdepth> corresponds to the
 * maximum recursion depth permitted, it is decremented on each recursive
 * call and the parsing will fail one reaching <= 0.
 */
int cfg_parse_cond_and(const char **text, struct cfg_cond_and **expr, char **err, const char **errptr, int maxdepth)
{
	struct cfg_cond_and *e;
	const char *in = *text;
	int ret = -1;

	if (!*in) /* empty expr does not parse */
		return 0;

	*expr = NULL;
	if (maxdepth <= 0) {
		memprintf(err, "unparsable conditional sub-expression '%s'", in);
		if (errptr)
			*errptr = in;
		goto done;
	}

	e = *expr = calloc(1, sizeof(**expr));
	if (!e) {
		memprintf(err, "memory allocation error while parsing conditional expression '%s'", *text);
		goto done;
	}

	ret = cfg_parse_cond_term(&in, &e->left, err, errptr, maxdepth - 1);
	if (ret == -1) // parse error, error already reported
		goto done;

	if (ret == 0) {
		/* ret == 0, no other way to parse this */
		memprintf(err, "unparsable conditional sub-expression '%s'", in);
		if (errptr)
			*errptr = in;
		ret = -1;
		goto done;
	}

	/* ret=1, we have a term in the left hand set */

	/* find an optional '&&' */
	while (*in == ' ' || *in == '\t')
		in++;

	*text = in;
	if (in[0] != '&' || in[1] != '&')
		goto done;

	/* we have a '&&', let's parse the right handset's subexp */
	in += 2;
	while (*in == ' ' || *in == '\t')
		in++;

	ret = cfg_parse_cond_and(&in, &e->right, err, errptr, maxdepth - 1);
	if (ret > 0)
		*text = in;
 done:
	if (ret < 0) {
		cfg_free_cond_and(*expr);
		*expr = NULL;
	}
	return ret;
}

/* Parse an indirect input text as a possible config condition term.
 * Returns <0 on parsing error, 0 if the parser is desynchronized, or >0 on
 * success. <expr> is filled with the parsed info, and <text> is updated on
 * success to point to the first unparsed character, or is left untouched
 * on failure. On success, the caller will have to free all lower-level
 * allocated structs using cfg_free_cond_expr(). An error will be set in
 * <err> on error, and only in this case. In this case the first bad
 * character will be reported in <errptr>. <maxdepth> corresponds to the
 * maximum recursion depth permitted, it is decremented on each recursive call
 * and the parsing will fail one reaching <= 0.
 */
int cfg_parse_cond_expr(const char **text, struct cfg_cond_expr **expr, char **err, const char **errptr, int maxdepth)
{
	struct cfg_cond_expr *e;
	const char *in = *text;
	int ret = -1;

	if (!*in) /* empty expr does not parse */
		return 0;

	*expr = NULL;
	if (maxdepth <= 0) {
		memprintf(err, "unparsable conditional expression '%s'", in);
		if (errptr)
			*errptr = in;
		goto done;
	}

	e = *expr = calloc(1, sizeof(**expr));
	if (!e) {
		memprintf(err, "memory allocation error while parsing conditional expression '%s'", *text);
		goto done;
	}

	ret = cfg_parse_cond_and(&in, &e->left, err, errptr, maxdepth - 1);
	if (ret == -1) // parse error, error already reported
		goto done;

	if (ret == 0) {
		/* ret == 0, no other way to parse this */
		memprintf(err, "unparsable conditional expression '%s'", in);
		if (errptr)
			*errptr = in;
		ret = -1;
		goto done;
	}

	/* ret=1, we have a sub-expr in the left hand set */

	/* find an optional '||' */
	while (*in == ' ' || *in == '\t')
		in++;

	*text = in;
	if (in[0] != '|' || in[1] != '|')
		goto done;

	/* we have a '||', let's parse the right handset's subexp */
	in += 2;
	while (*in == ' ' || *in == '\t')
		in++;

	ret = cfg_parse_cond_expr(&in, &e->right, err, errptr, maxdepth - 1);
	if (ret > 0)
		*text = in;
 done:
	if (ret < 0) {
		cfg_free_cond_expr(*expr);
		*expr = NULL;
	}
	return ret;
}

/* evaluate an sub-expression on a .if/.elif line. The expression is valid and
 * was already parsed in <expr>. Returns -1 on error (in which case err is
 * filled with a message, and only in this case), 0 if the condition is false,
 * 1 if it's true.
 */
int cfg_eval_cond_and(struct cfg_cond_and *expr, char **err)
{
	int ret;

	/* AND: loop on terms and sub-exp's terms as long as they're TRUE
	 * (stop on FALSE and ERROR).
	 */
	while ((ret = cfg_eval_cond_term(expr->left, err)) > 0 && expr->right)
		expr = expr->right;
	return ret;
}

/* evaluate an expression on a .if/.elif line. The expression is valid and was
 * already parsed in <expr>. Returns -1 on error (in which case err is filled
 * with a message, and only in this case), 0 if the condition is false, 1 if
 * it's true.
 */
int cfg_eval_cond_expr(struct cfg_cond_expr *expr, char **err)
{
	int ret;

	/* OR: loop on sub-exps as long as they're FALSE (stop on TRUE and ERROR) */
	while ((ret = cfg_eval_cond_and(expr->left, err)) == 0 && expr->right)
		expr = expr->right;
	return ret;
}

/* evaluate a condition on a .if/.elif line. The condition is already tokenized
 * in <err>. Returns -1 on error (in which case err is filled with a message,
 * and only in this case), 0 if the condition is false, 1 if it's true. If
 * <errptr> is not NULL, it's set to the first invalid character on error.
 */
int cfg_eval_condition(char **args, char **err, const char **errptr)
{
	struct cfg_cond_expr *expr = NULL;
	const char *text = args[0];
	int ret = -1;

	if (!*text) /* note: empty = false */
		return 0;

	ret = cfg_parse_cond_expr(&text, &expr, err, errptr, MAX_CFG_RECURSION);
	if (ret != 0) {
		if (ret == -1) // parse error, error already reported
			goto done;
		while (*text == ' ' || *text == '\t')
			text++;

		if (*text) {
			ret = -1;
			memprintf(err, "unexpected character '%c' at the end of conditional expression '%s'",
				  *text, args[0]);
			goto fail;
		}

		ret = cfg_eval_cond_expr(expr, err);
		goto done;
	}

	/* ret == 0, no other way to parse this */
	ret = -1;
	memprintf(err, "unparsable conditional expression '%s'", args[0]);
 fail:
	if (errptr)
		*errptr = text;
 done:
	cfg_free_cond_expr(expr);
	return ret;
}
