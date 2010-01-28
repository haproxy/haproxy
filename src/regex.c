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
#include <common/regex.h>
#include <common/standard.h>
#include <proto/log.h>

/* regex trash buffer used by various regex tests */
regmatch_t pmatch[MAX_MATCH];  /* rm_so, rm_eo for regular expressions */


int exp_replace(char *dst, char *src, const char *str, const regmatch_t *matches)
{
	char *old_dst = dst;

	while (*str) {
		if (*str == '\\') {
			str++;
			if (isdigit((unsigned char)*str)) {
				int len, num;

				num = *str - '0';
				str++;

				if (matches[num].rm_eo > -1 && matches[num].rm_so > -1) {
					len = matches[num].rm_eo - matches[num].rm_so;
					memcpy(dst, src + matches[num].rm_so, len);
					dst += len;
				}
		
			} else if (*str == 'x') {
				unsigned char hex1, hex2;
				str++;

				hex1 = toupper(*str++) - '0';
				hex2 = toupper(*str++) - '0';

				if (hex1 > 9) hex1 -= 'A' - '9' - 1;
				if (hex2 > 9) hex2 -= 'A' - '9' - 1;
				*dst++ = (hex1<<4) + hex2;
			} else {
				*dst++ = *str++;
			}
		} else {
			*dst++ = *str++;
		}
	}
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
const char *chain_regex(struct hdr_exp **head, const regex_t *preg,
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



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
