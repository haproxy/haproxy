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

/* evaluate a condition on a .if/.elif line. The condition is already tokenized
 * in <err>. Returns -1 on error (in which case err is filled with a message,
 * and only in this case), 0 if the condition is false, 1 if it's true. If
 * <errptr> is not NULL, it's set to the first invalid character on error.
 */
int cfg_eval_condition(char **args, char **err, const char **errptr)
{
	const struct cond_pred_kw *cond_pred = NULL;
	const char *end_ptr;
	struct arg *argp = NULL;
	int err_arg;
	int nbargs;
	int ret = -1;
	char *end;
	long val;

	if (!*args[0]) /* note: empty = false */
		return 0;

	val = strtol(args[0], &end, 0);
	if (end && *end == '\0')
		return val != 0;

	/* below we'll likely all make_arg_list() so we must return only via
	 * the <done> label which frees the arg list.
	 */
	cond_pred = cfg_lookup_cond_pred(args[0]);
	if (cond_pred) {
		nbargs = make_arg_list(args[0] + strlen(cond_pred->word), -1,
		                       cond_pred->arg_mask, &argp, err,
		                       &end_ptr, &err_arg, NULL);

		if (nbargs < 0) {
			memprintf(err, "%s in argument %d of predicate '%s' used in conditional expression", *err, err_arg, cond_pred->word);
			if (errptr)
				*errptr = end_ptr;
			goto done;
		}

		/* here we know we have a valid predicate with <nbargs> valid
		 * arguments, placed in <argp> (which we'll need to free).
		 */
		switch (cond_pred->prd) {
		case CFG_PRED_DEFINED:  // checks if arg exists as an environment variable
			ret = getenv(argp[0].data.str.area) != NULL;
			goto done;

		case CFG_PRED_FEATURE: { // checks if the arg matches an enabled feature
			const char *p;

			for (p = build_features; (p = strstr(p, argp[0].data.str.area)); p++) {
				if ((p[argp[0].data.str.data] == ' ' || p[argp[0].data.str.data] == 0) &&
				    p > build_features) {
					if (*(p-1) == '+') { // "+OPENSSL"
						ret = 1;
						goto done;
					}
					else if (*(p-1) == '-') { // "-OPENSSL"
						ret = 0;
						goto done;
					}
					/* it was a sub-word, let's restart from next place */
				}
			}
			/* not found */
			ret = 0;
			goto done;
		}
		case CFG_PRED_STREQ:    // checks if the two arg are equal
			ret = strcmp(argp[0].data.str.area, argp[1].data.str.area) == 0;
			goto done;

		case CFG_PRED_STRNEQ:   // checks if the two arg are different
			ret = strcmp(argp[0].data.str.area, argp[1].data.str.area) != 0;
			goto done;

		case CFG_PRED_VERSION_ATLEAST: // checks if the current version is at least this one
			ret = compare_current_version(argp[0].data.str.area) <= 0;
			goto done;

		case CFG_PRED_VERSION_BEFORE:  // checks if the current version is older than this one
			ret = compare_current_version(argp[0].data.str.area) > 0;
			goto done;

		default:
			memprintf(err, "internal error: unhandled conditional expression predicate '%s'", cond_pred->word);
			if (errptr)
				*errptr = args[0];
			goto done;
		}
	}

	memprintf(err, "unparsable conditional expression '%s'", args[0]);
	if (errptr)
		*errptr = args[0];
 done:
	free_args(argp);
	ha_free(&argp);
	return ret;
}
