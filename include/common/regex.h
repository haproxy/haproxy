/*
 * include/common/regex.h
 * This file defines everything related to regular expressions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_REGEX_H
#define _COMMON_REGEX_H

#include <stdlib.h>
#include <string.h>

#include <common/config.h>

#ifdef USE_PCRE
#include <pcre.h>
#include <pcreposix.h>

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

#elif USE_PCRE2
#include <pcre2.h>
#include <pcre2posix.h>

#else /* no PCRE, nor PCRE2 */
#include <regex.h>
#endif

struct my_regex {
#ifdef USE_PCRE
	pcre *reg;
	pcre_extra *extra;
#ifdef USE_PCRE_JIT
#ifndef PCRE_CONFIG_JIT
#error "The PCRE lib doesn't support JIT. Change your lib, or remove the option USE_PCRE_JIT."
#endif
#endif
#elif USE_PCRE2
	pcre2_code *reg;
#else /* no PCRE */
	regex_t regex;
#endif
};

/* what to do when a header matches a regex */
#define ACT_ALLOW	0	/* allow the request */
#define ACT_REPLACE	1	/* replace the matching header */
#define ACT_REMOVE	2	/* remove the matching header */
#define ACT_DENY	3	/* deny the request */
#define ACT_PASS	4	/* pass this header without allowing or denying the request */
#define ACT_TARPIT	5	/* tarpit the connection matching this request */

struct hdr_exp {
    struct hdr_exp *next;
    struct my_regex *preg;		/* expression to look for */
    int action;				/* ACT_ALLOW, ACT_REPLACE, ACT_REMOVE, ACT_DENY */
    const char *replace;		/* expression to set instead */
    void *cond;				/* a possible condition or NULL */
};

extern THREAD_LOCAL regmatch_t pmatch[MAX_MATCH];

/* "str" is the string that contain the regex to compile.
 * "regex" is preallocated memory. After the execution of this function, this
 *         struct contain the compiled regex.
 * "cs" is the case sensitive flag. If cs is true, case sensitive is enabled.
 * "cap" is capture flag. If cap if true the regex can capture into
 *       parenthesis strings.
 * "err" is the standar error message pointer.
 *
 * The function return 1 is succes case, else return 0 and err is filled.
 */
struct my_regex *regex_comp(const char *str, int cs, int cap, char **err);
int exp_replace(char *dst, unsigned int dst_size, char *src, const char *str, const regmatch_t *matches);
const char *check_replace_string(const char *str);
const char *chain_regex(struct hdr_exp **head, struct my_regex *preg,
			int action, const char *replace, void *cond);

/* If the function doesn't match, it returns false, else it returns true.
 */
static inline int regex_exec(const struct my_regex *preg, char *subject) {
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	if (pcre_exec(preg->reg, preg->extra, subject, strlen(subject), 0, 0, NULL, 0) < 0)
		return 0;
	return 1;
#elif defined(USE_PCRE2)
	pcre2_match_data *pm;
	int ret;

	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = pcre2_match(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject),
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
static inline int regex_exec2(const struct my_regex *preg, char *subject, int length) {
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	if (pcre_exec(preg->reg, preg->extra, subject, length, 0, 0, NULL, 0) < 0)
		return 0;
	return 1;
#elif defined(USE_PCRE2)
	pcre2_match_data *pm;
	int ret;

	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = pcre2_match(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)length,
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

int regex_exec_match(const struct my_regex *preg, const char *subject,
                     size_t nmatch, regmatch_t pmatch[], int flags);
int regex_exec_match2(const struct my_regex *preg, char *subject, int length,
                      size_t nmatch, regmatch_t pmatch[], int flags);

static inline void regex_free(struct my_regex *preg) {
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

#endif /* _COMMON_REGEX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
