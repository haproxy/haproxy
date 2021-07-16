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
#include <haproxy/global.h>
#include <haproxy/tools.h>

/* supported condition predicates */
const struct cond_pred_kw cond_predicates[] = {
	{ "defined",          CFG_PRED_DEFINED,         ARG1(1, STR)         },
	{ "feature",          CFG_PRED_FEATURE,         ARG1(1, STR)         },
	{ "streq",            CFG_PRED_STREQ,           ARG2(2, STR, STR)    },
	{ "strneq",           CFG_PRED_STRNEQ,          ARG2(2, STR, STR)    },
	{ "version_atleast",  CFG_PRED_VERSION_ATLEAST, ARG1(1, STR)         },
	{ "version_before",   CFG_PRED_VERSION_BEFORE,  ARG1(1, STR)         },
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

/* Parse an indirect input text as a possible config condition term.
 * Returns <0 on parsing error, 0 if the parser is desynchronized, or >0 on
 * success. <term> is filled with the parsed info, and <text> is updated on
 * success to point to the first unparsed character, or is left untouched
 * on failure. On success, the caller must free term->args using free_args()
 * and free the array itself. An error will be set in <err> on error, and only
 * in this case. In this case the first bad character will be reported in
 * <errptr>.
 */
int cfg_parse_cond_term(const char **text, struct cfg_cond_term *term, char **err, const char **errptr)
{
	const char *in = *text;
	const char *end_ptr;
	int err_arg;
	int nbargs;
	char *end;
	long val;

	term->type = CCTT_NONE;
	term->args = NULL;
	term->neg  = 0;

	while (*in == ' ' || *in == '\t')
		in++;

	if (!*in) /* empty term does not parse */
		return 0;

	/* !<term> negates the term. White spaces permitted */
	while (*in == '!') {
		term->neg = !term->neg;
		do { in++; } while (*in == ' ' || *in == '\t');
	}

	val = strtol(in, &end, 0);
	if (end != in) {
		term->type = val ? CCTT_TRUE : CCTT_FALSE;
		*text = end;
		return 1;
	}

	/* below we'll likely all make_arg_list() so we must return only via
	 * the <done> label which frees the arg list.
	 */
	term->pred = cfg_lookup_cond_pred(in);
	if (term->pred) {
		term->type = CCTT_PRED;
		nbargs = make_arg_list(in + strlen(term->pred->word), -1,
		                       term->pred->arg_mask, &term->args, err,
		                       &end_ptr, &err_arg, NULL);
		if (nbargs < 0) {
			free_args(term->args);
			ha_free(&term->args);
			memprintf(err, "%s in argument %d of predicate '%s' used in conditional expression", *err, err_arg, term->pred->word);
			if (errptr)
				*errptr = end_ptr;
			return -1;
		}
		*text = end_ptr;
		return 1;
	}

	memprintf(err, "unparsable conditional expression '%s'", *text);
	if (errptr)
		*errptr = *text;
	return -1;
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

		case CFG_PRED_VERSION_ATLEAST: // checks if the current version is at least this one
			ret = compare_current_version(term->args[0].data.str.area) <= 0;
			break;

		case CFG_PRED_VERSION_BEFORE:  // checks if the current version is older than this one
			ret = compare_current_version(term->args[0].data.str.area) > 0;
			break;

		default:
			memprintf(err, "internal error: unhandled conditional expression predicate '%s'", term->pred->word);
			break;
		}
	}
	else {
		memprintf(err, "internal error: unhandled condition term type %d", (int)term->type);
	}

	if (ret >= 0 && term->neg)
		ret = !ret;
	return ret;
}


/* evaluate a condition on a .if/.elif line. The condition is already tokenized
 * in <err>. Returns -1 on error (in which case err is filled with a message,
 * and only in this case), 0 if the condition is false, 1 if it's true. If
 * <errptr> is not NULL, it's set to the first invalid character on error.
 */
int cfg_eval_condition(char **args, char **err, const char **errptr)
{
	struct cfg_cond_term term = { };
	const char *text = args[0];
	int ret = -1;

	if (!*text) /* note: empty = false */
		return 0;

	ret = cfg_parse_cond_term(&text, &term, err, errptr);
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

		ret = cfg_eval_cond_term(&term, err);
		goto done;
	}

	/* ret == 0, no other way to parse this */
	ret = -1;
	memprintf(err, "unparsable conditional expression '%s'", args[0]);
 fail:
	if (errptr)
		*errptr = text;
 done:
	free_args(term.args);
	ha_free(&term.args);
	return ret;
}
