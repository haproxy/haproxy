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

#include <types/global.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/regex.h>
#include <common/standard.h>
#include <proto/log.h>

/* regex trash buffer used by various regex tests */
THREAD_LOCAL regmatch_t pmatch[MAX_MATCH];  /* rm_so, rm_eo for regular expressions */

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
				ha_warning("'\\%c' : deprecated use of a backslash before something not '\\','x' or a digit.\n", *str);
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

	exp = calloc(1, sizeof(*exp));

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
#if defined(USE_PCRE) || defined(USE_PCRE_JIT) || defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	int ret;
#ifdef USE_PCRE2
	PCRE2_SIZE *matches;
	pcre2_match_data *pm;
#else
	int matches[MAX_MATCH * 3];
#endif
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
#ifdef USE_PCRE2
		options |= PCRE2_NOTBOL;
#else
		options |= PCRE_NOTBOL;
#endif

	/* The value returned by pcre_exec()/pcre2_match() is one more than the highest numbered
	 * pair that has been set. For example, if two substrings have been captured,
	 * the returned value is 3. If there are no capturing subpatterns, the return
	 * value from a successful match is 1, indicating that just the first pair of
	 * offsets has been set.
	 *
	 * It seems that this function returns 0 if it detects more matches than available
	 * space in the matches array.
	 */
#ifdef USE_PCRE2
	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = pcre2_match(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject), 0, options, pm, NULL);

	if (ret < 0) {
		pcre2_match_data_free(pm);
		return 0;
	}

	matches = pcre2_get_ovector_pointer(pm);
#else
	ret = pcre_exec(preg->reg, preg->extra, subject, strlen(subject), 0, options, matches, enmatch * 3);

	if (ret < 0)
		return 0;
#endif

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
#ifdef USE_PCRE2
	pcre2_match_data_free(pm);
#endif
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
#if defined(USE_PCRE) || defined(USE_PCRE_JIT) || defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	int ret;
#ifdef USE_PCRE2
	PCRE2_SIZE *matches;
	pcre2_match_data *pm;
#else
	int matches[MAX_MATCH * 3];
#endif
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
#ifdef USE_PCRE2
		options |= PCRE2_NOTBOL;
#else
		options |= PCRE_NOTBOL;
#endif

	/* The value returned by pcre_exec()/pcre2_match() is one more than the highest numbered
	 * pair that has been set. For example, if two substrings have been captured,
	 * the returned value is 3. If there are no capturing subpatterns, the return
	 * value from a successful match is 1, indicating that just the first pair of
	 * offsets has been set.
	 *
	 * It seems that this function returns 0 if it detects more matches than available
	 * space in the matches array.
	 */
#ifdef USE_PCRE2
	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = pcre2_match(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)length, 0, options, pm, NULL);

	if (ret < 0) {
		pcre2_match_data_free(pm);
		return 0;
	}

	matches = pcre2_get_ovector_pointer(pm);
#else
	ret = pcre_exec(preg->reg, preg->extra, subject, length, 0, options, matches, enmatch * 3);
	if (ret < 0)
		return 0;
#endif

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
#ifdef USE_PCRE2
	pcre2_match_data_free(pm);
#endif
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

struct my_regex *regex_comp(const char *str, int cs, int cap, char **err)
{
	struct my_regex *regex = NULL;
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int flags = 0;
	const char *error;
	int erroffset;
#elif defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	int flags = 0;
	int errn;
#if defined(USE_PCRE2_JIT)
	int jit;
#endif
	PCRE2_UCHAR error[256];
	PCRE2_SIZE erroffset;
#else
	int flags = REG_EXTENDED;
#endif

	regex = calloc(1, sizeof(*regex));
	if (!regex) {
		memprintf(err, "not enough memory to build regex");
		goto out_fail_alloc;
	}

#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	if (!cs)
		flags |= PCRE_CASELESS;
	if (!cap)
		flags |= PCRE_NO_AUTO_CAPTURE;

	regex->reg = pcre_compile(str, flags, &error, &erroffset, NULL);
	if (!regex->reg) {
		memprintf(err, "regex '%s' is invalid (error=%s, erroffset=%d)", str, error, erroffset);
		goto out_fail_alloc;
	}

	regex->extra = pcre_study(regex->reg, PCRE_STUDY_JIT_COMPILE, &error);
	if (!regex->extra && error != NULL) {
		pcre_free(regex->reg);
		memprintf(err, "failed to compile regex '%s' (error=%s)", str, error);
		goto out_fail_alloc;
	}
#elif defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	if (!cs)
		flags |= PCRE2_CASELESS;
	if (!cap)
		flags |= PCRE2_NO_AUTO_CAPTURE;

	regex->reg = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED, flags, &errn, &erroffset, NULL);
	if (!regex->reg) {
		pcre2_get_error_message(errn, error, sizeof(error));
		memprintf(err, "regex '%s' is invalid (error=%s, erroffset=%zu)", str, error, erroffset);
		goto out_fail_alloc;
	}

#if defined(USE_PCRE2_JIT)
	jit = pcre2_jit_compile(regex->reg, PCRE2_JIT_COMPLETE);
	/*
	 * We end if it is an error not related to lack of JIT support
	 * in a case of JIT support missing pcre2_jit_compile is "no-op"
	 */
	if (jit < 0 && jit != PCRE2_ERROR_JIT_BADOPTION) {
		pcre2_code_free(regex->reg);
		memprintf(err, "regex '%s' jit compilation failed", str);
		goto out_fail_alloc;
	}
#endif

#else
	if (!cs)
		flags |= REG_ICASE;
	if (!cap)
		flags |= REG_NOSUB;

	if (regcomp(&regex->regex, str, flags) != 0) {
		memprintf(err, "regex '%s' is invalid", str);
		goto out_fail_alloc;
	}
#endif
	return regex;

  out_fail_alloc:
	free(regex);
	return NULL;
}

static void regex_register_build_options(void)
{
	char *ptr = NULL;

#ifdef USE_PCRE
	memprintf(&ptr, "Built with PCRE version : %s", (HAP_XSTRING(Z PCRE_PRERELEASE)[1] == 0)?
		HAP_XSTRING(PCRE_MAJOR.PCRE_MINOR PCRE_DATE) :
		HAP_XSTRING(PCRE_MAJOR.PCRE_MINOR) HAP_XSTRING(PCRE_PRERELEASE PCRE_DATE));
	memprintf(&ptr, "%s\nRunning on PCRE version : %s", ptr, pcre_version());

	memprintf(&ptr, "%s\nPCRE library supports JIT : %s", ptr,
#ifdef USE_PCRE_JIT
		  ({
			  int r;
			  pcre_config(PCRE_CONFIG_JIT, &r);
			  r ? "yes" : "no (libpcre build without JIT?)";
		  })
#else
		  "no (USE_PCRE_JIT not set)"
#endif
		  );
#endif /* USE_PCRE */

#ifdef USE_PCRE2
	memprintf(&ptr, "Built with PCRE2 version : %s", (HAP_XSTRING(Z PCRE2_PRERELEASE)[1] == 0) ?
	          HAP_XSTRING(PCRE2_MAJOR.PCRE2_MINOR PCRE2_DATE) :
	          HAP_XSTRING(PCRE2_MAJOR.PCRE2_MINOR) HAP_XSTRING(PCRE2_PRERELEASE PCRE2_DATE));
	memprintf(&ptr, "%s\nPCRE2 library supports JIT : %s", ptr,
#ifdef USE_PCRE2_JIT
		  ({
			  int r;
			  pcre2_config(PCRE2_CONFIG_JIT, &r);
			  r ? "yes" : "no (libpcre2 build without JIT?)";
		  })
#else
		  "no (USE_PCRE2_JIT not set)"
#endif
		  );
#endif /* USE_PCRE2 */

#if !defined(USE_PCRE) && !defined(USE_PCRE2)
	memprintf(&ptr, "Built without PCRE or PCRE2 support (using libc's regex instead)");
#endif
	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, regex_register_build_options);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
