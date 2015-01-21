/*
 * Regex and string management functions.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <common/config.h>
#include <common/defaults.h>
#include <common/regex.h>
#include <common/standard.h>
#include <proto/log.h>

/* regex trash buffer used by various regex tests */
regmatch_t pmatch[MAX_MATCH];  /* rm_so, rm_eo for regular expressions */

int exp_replace(char *dst, unsigned int dst_size, char *src, const char *str, const regmatch_t *matches)
{
	char *old_dst = dst;
	char* dst_end = dst + dst_size;

	while (*str) {
		if (*str == '\\') {
			str++;
			if (!*str)
				return -1;

			if (isdigit((unsigned char)*str)) {
				int len, num;

				num = *str - '0';
				str++;

				if (matches[num].rm_eo > -1 && matches[num].rm_so > -1) {
					len = matches[num].rm_eo - matches[num].rm_so;

					if (dst + len >= dst_end)
						return -1;

					memcpy(dst, src + matches[num].rm_so, len);
					dst += len;
				}
		
			} else if (*str == 'x') {
				unsigned char hex1, hex2;
				str++;

				if (!*str)
					return -1;

				hex1 = toupper(*str++) - '0';

				if (!*str)
					return -1;

				hex2 = toupper(*str++) - '0';

				if (hex1 > 9) hex1 -= 'A' - '9' - 1;
				if (hex2 > 9) hex2 -= 'A' - '9' - 1;

				if (dst >= dst_end)
					return -1;

				*dst++ = (hex1<<4) + hex2;
			} else {
				if (dst >= dst_end)
					return -1;

				*dst++ = *str++;
			}
		} else {
			if (dst >= dst_end)
				return -1;

			*dst++ = *str++;
		}
	}
	if (dst >= dst_end)
		return -1;

	*dst = '\0';
	return dst - old_dst;
}

/* returns NULL if the replacement string <str> is valid, or the pointer to the first error */
const char *check_replace_string(const char *str)
{
	const char *err = NULL;
	while (*str) {
		if (*str == '\\') {
			err = str; /* in case of a backslash, we return the pointer to it */
			str++;
			if (!*str)
				return err;
			else if (isdigit((unsigned char)*str))
				err = NULL;
			else if (*str == 'x') {
				str++;
				if (!ishex(*str))
					return err;
				str++;
				if (!ishex(*str))
					return err;
				err = NULL;
			}
			else {
				Warning("'\\%c' : deprecated use of a backslash before something not '\\','x' or a digit.\n", *str);
				err = NULL;
			}
		}
		str++;
	}
	return err;
}


/* returns the pointer to an error in the replacement string, or NULL if OK */
const char *chain_regex(struct hdr_exp **head, struct my_regex *preg,
			int action, const char *replace, void *cond)
{
	struct hdr_exp *exp;

	if (replace != NULL) {
		const char *err;
		err = check_replace_string(replace);
		if (err)
			return err;
	}

	while (*head != NULL)
		head = &(*head)->next;

	exp = calloc(1, sizeof(struct hdr_exp));

	exp->preg = preg;
	exp->replace = replace;
	exp->action = action;
	exp->cond = cond;
	*head = exp;

	return NULL;
}

/* This function apply regex. It take const null terminated char as input.
 * If the function doesn't match, it returns false, else it returns true.
 * When it is compiled with JIT, this function execute strlen on the subject.
 * Currently the only supported flag is REG_NOTBOL.
 */
int regex_exec_match(const struct my_regex *preg, const char *subject,
                     size_t nmatch, regmatch_t pmatch[], int flags) {
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int ret;
	int matches[MAX_MATCH * 3];
	int enmatch;
	int i;
	int options;

	/* Silently limit the number of allowed matches. max
	 * match i the maximum value for match, in fact this
	 * limit is not applyied.
	 */
	enmatch = nmatch;
	if (enmatch > MAX_MATCH)
		enmatch = MAX_MATCH;

	options = 0;
	if (flags & REG_NOTBOL)
		options |= PCRE_NOTBOL;

	/* The value returned by pcre_exec() is one more than the highest numbered
	 * pair that has been set. For example, if two substrings have been captured,
	 * the returned value is 3. If there are no capturing subpatterns, the return
	 * value from a successful match is 1, indicating that just the first pair of
	 * offsets has been set.
	 *
	 * It seems that this function returns 0 if it detect more matches than avalaible
	 * space in the matches array.
	 */
	ret = pcre_exec(preg->reg, preg->extra, subject, strlen(subject), 0, options, matches, enmatch * 3);
	if (ret < 0)
		return 0;

	if (ret == 0)
		ret = enmatch;

	for (i=0; i<nmatch; i++) {
		/* Copy offset. */
		if (i < ret) {
			pmatch[i].rm_so = matches[(i*2)];
			pmatch[i].rm_eo = matches[(i*2)+1];
			continue;
		}
		/* Set the unmatvh flag (-1). */
		pmatch[i].rm_so = -1;
		pmatch[i].rm_eo = -1;
	}
	return 1;
#else
	int match;

	flags &= REG_NOTBOL;
	match = regexec(&preg->regex, subject, nmatch, pmatch, flags);
	if (match == REG_NOMATCH)
		return 0;
	return 1;
#endif
}

/* This function apply regex. It take a "char *" ans length as input. The
 * <subject> can be modified during the processing. If the function doesn't
 * match, it returns false, else it returns true.
 * When it is compiled with standard POSIX regex or PCRE, this function add
 * a temporary null chracters at the end of the <subject>. The <subject> must
 * have a real length of <length> + 1. Currently the only supported flag is
 * REG_NOTBOL.
 */
int regex_exec_match2(const struct my_regex *preg, char *subject, int length,
                      size_t nmatch, regmatch_t pmatch[], int flags) {
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int ret;
	int matches[MAX_MATCH * 3];
	int enmatch;
	int i;
	int options;

	/* Silently limit the number of allowed matches. max
	 * match i the maximum value for match, in fact this
	 * limit is not applyied.
	 */
	enmatch = nmatch;
	if (enmatch > MAX_MATCH)
		enmatch = MAX_MATCH;

	options = 0;
	if (flags & REG_NOTBOL)
		options |= PCRE_NOTBOL;

	/* The value returned by pcre_exec() is one more than the highest numbered
	 * pair that has been set. For example, if two substrings have been captured,
	 * the returned value is 3. If there are no capturing subpatterns, the return
	 * value from a successful match is 1, indicating that just the first pair of
	 * offsets has been set.
	 *
	 * It seems that this function returns 0 if it detect more matches than avalaible
	 * space in the matches array.
	 */
	ret = pcre_exec(preg->reg, preg->extra, subject, length, 0, options, matches, enmatch * 3);
	if (ret < 0)
		return 0;

	if (ret == 0)
		ret = enmatch;

	for (i=0; i<nmatch; i++) {
		/* Copy offset. */
		if (i < ret) {
			pmatch[i].rm_so = matches[(i*2)];
			pmatch[i].rm_eo = matches[(i*2)+1];
			continue;
		}
		/* Set the unmatvh flag (-1). */
		pmatch[i].rm_so = -1;
		pmatch[i].rm_eo = -1;
	}
	return 1;
#else
	char old_char = subject[length];
	int match;

	flags &= REG_NOTBOL;
	subject[length] = 0;
	match = regexec(&preg->regex, subject, nmatch, pmatch, flags);
	subject[length] = old_char;
	if (match == REG_NOMATCH)
		return 0;
	return 1;
#endif
}

int regex_comp(const char *str, struct my_regex *regex, int cs, int cap, char **err)
{
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int flags = 0;
	const char *error;
	int erroffset;

	if (!cs)
		flags |= PCRE_CASELESS;
	if (!cap)
		flags |= PCRE_NO_AUTO_CAPTURE;

	regex->reg = pcre_compile(str, flags, &error, &erroffset, NULL);
	if (!regex->reg) {
		memprintf(err, "regex '%s' is invalid (error=%s, erroffset=%d)", str, error, erroffset);
		return 0;
	}

	regex->extra = pcre_study(regex->reg, PCRE_STUDY_JIT_COMPILE, &error);
	if (!regex->extra && error != NULL) {
		pcre_free(regex->reg);
		memprintf(err, "failed to compile regex '%s' (error=%s)", str, error);
		return 0;
	}
#else
	int flags = REG_EXTENDED;

	if (!cs)
		flags |= REG_ICASE;
	if (!cap)
		flags |= REG_NOSUB;

	if (regcomp(&regex->regex, str, flags) != 0) {
		memprintf(err, "regex '%s' is invalid", str);
		return 0;
	}
#endif
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
