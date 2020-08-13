/*
 * include/haproxy/regex.h
 * Compatibility layer for various regular expression engines
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_REGEX_H
#define _HAPROXY_REGEX_H

#include <stdlib.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/regex-t.h>

extern THREAD_LOCAL regmatch_t pmatch[MAX_MATCH];

/* "str" is the string that contain the regex to compile.
 * "regex" is preallocated memory. After the execution of this function, this
 *         struct contain the compiled regex.
 * "cs" is the case sensitive flag. If cs is true, case sensitive is enabled.
 * "cap" is capture flag. If cap if true the regex can capture into
 *       parenthesis strings.
 * "err" is the standard error message pointer.
 *
 * The function return 1 is success case, else return 0 and err is filled.
 */
struct my_regex *regex_comp(const char *str, int cs, int cap, char **err);
int exp_replace(char *dst, unsigned int dst_size, char *src, const char *str, const regmatch_t *matches);
const char *check_replace_string(const char *str);
int regex_exec_match(const struct my_regex *preg, const char *subject,
                     size_t nmatch, regmatch_t pmatch[], int flags);
int regex_exec_match2(const struct my_regex *preg, char *subject, int length,
                      size_t nmatch, regmatch_t pmatch[], int flags);


/* If the function doesn't match, it returns false, else it returns true.
 */
static inline int regex_exec(const struct my_regex *preg, char *subject)
{
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	if (pcre_exec(preg->reg, preg->extra, subject, strlen(subject), 0, 0, NULL, 0) < 0)
		return 0;
	return 1;
#elif defined(USE_PCRE2)
	pcre2_match_data *pm;
	int ret;

	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = preg->mfn(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject),
		0, 0, pm, NULL);
	pcre2_match_data_free(pm);
	if (ret < 0)
		return 0;
	return 1;
#else
	int match;
	match = regexec(&preg->regex, subject, 0, NULL, 0);
	if (match == REG_NOMATCH)
		return 0;
	return 1;
#endif
}

/* Note that <subject> MUST be at least <length+1> characters long and must
 * be writable because the function will temporarily force a zero past the
 * last character.
 *
 * If the function doesn't match, it returns false, else it returns true.
 */
static inline int regex_exec2(const struct my_regex *preg, char *subject, int length)
{
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	if (pcre_exec(preg->reg, preg->extra, subject, length, 0, 0, NULL, 0) < 0)
		return 0;
	return 1;
#elif defined(USE_PCRE2)
	pcre2_match_data *pm;
	int ret;

	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = preg->mfn(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)length,
		0, 0, pm, NULL);
	pcre2_match_data_free(pm);
	if (ret < 0)
		return 0;
	return 1;
#else
	int match;
	char old_char = subject[length];
	subject[length] = 0;
	match = regexec(&preg->regex, subject, 0, NULL, 0);
	subject[length] = old_char;
	if (match == REG_NOMATCH)
		return 0;
	return 1;
#endif
}

static inline void regex_free(struct my_regex *preg)
{
	if (!preg)
		return;
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	pcre_free(preg->reg);
/* PCRE < 8.20 requires pcre_free() while >= 8.20 requires pcre_study_free(),
 * which is easily detected using PCRE_CONFIG_JIT.
 */
#ifdef PCRE_CONFIG_JIT
	pcre_free_study(preg->extra);
#else /* PCRE_CONFIG_JIT */
	pcre_free(preg->extra);
#endif /* PCRE_CONFIG_JIT */
#elif defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	pcre2_code_free(preg->reg);
#else
	regfree(&preg->regex);
#endif
	free(preg);
}

#endif /* _HAPROXY_REGEX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
