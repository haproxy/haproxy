/*
 * HTTP ACLs declaration
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/http.h>
#include <common/initcall.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/pattern.h>


/* We use the pre-parsed method if it is known, and store its number as an
 * integer. If it is unknown, we use the pointer and the length.
 */
static int pat_parse_meth(const char *text, struct pattern *pattern, int mflags, char **err)
{
	int len, meth;

	len  = strlen(text);
	meth = find_http_meth(text, len);

	pattern->val.i = meth;
	if (meth == HTTP_METH_OTHER) {
		pattern->ptr.str = (char *)text;
		pattern->len = len;
	}
	else {
		pattern->ptr.str = NULL;
		pattern->len = 0;
	}
	return 1;
}

/* See above how the method is stored in the global pattern */
static struct pattern *pat_match_meth(struct sample *smp, struct pattern_expr *expr, int fill)
{
	int icase;
	struct pattern_list *lst;
	struct pattern *pattern;

	list_for_each_entry(lst, &expr->patterns, list) {
		pattern = &lst->pat;

		/* well-known method */
		if (pattern->val.i != HTTP_METH_OTHER) {
			if (smp->data.u.meth.meth == pattern->val.i)
				return pattern;
			else
				continue;
		}

		/* Other method, we must compare the strings */
		if (pattern->len != smp->data.u.meth.str.data)
			continue;

		icase = expr->mflags & PAT_MF_IGNORE_CASE;
		if ((icase && strncasecmp(pattern->ptr.str, smp->data.u.meth.str.area, smp->data.u.meth.str.data) == 0) ||
		    (!icase && strncmp(pattern->ptr.str, smp->data.u.meth.str.area, smp->data.u.meth.str.data) == 0))
			return pattern;
	}
	return NULL;
}

/************************************************************************/
/*          All supported ACL keywords must be declared here.           */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ "base",            "base",     PAT_MATCH_STR },
	{ "base_beg",        "base",     PAT_MATCH_BEG },
	{ "base_dir",        "base",     PAT_MATCH_DIR },
	{ "base_dom",        "base",     PAT_MATCH_DOM },
	{ "base_end",        "base",     PAT_MATCH_END },
	{ "base_len",        "base",     PAT_MATCH_LEN },
	{ "base_reg",        "base",     PAT_MATCH_REG },
	{ "base_sub",        "base",     PAT_MATCH_SUB },

	{ "cook",            "req.cook", PAT_MATCH_STR },
	{ "cook_beg",        "req.cook", PAT_MATCH_BEG },
	{ "cook_dir",        "req.cook", PAT_MATCH_DIR },
	{ "cook_dom",        "req.cook", PAT_MATCH_DOM },
	{ "cook_end",        "req.cook", PAT_MATCH_END },
	{ "cook_len",        "req.cook", PAT_MATCH_LEN },
	{ "cook_reg",        "req.cook", PAT_MATCH_REG },
	{ "cook_sub",        "req.cook", PAT_MATCH_SUB },

	{ "hdr",             "req.hdr",  PAT_MATCH_STR },
	{ "hdr_beg",         "req.hdr",  PAT_MATCH_BEG },
	{ "hdr_dir",         "req.hdr",  PAT_MATCH_DIR },
	{ "hdr_dom",         "req.hdr",  PAT_MATCH_DOM },
	{ "hdr_end",         "req.hdr",  PAT_MATCH_END },
	{ "hdr_len",         "req.hdr",  PAT_MATCH_LEN },
	{ "hdr_reg",         "req.hdr",  PAT_MATCH_REG },
	{ "hdr_sub",         "req.hdr",  PAT_MATCH_SUB },

	/* these two declarations uses strings with list storage (in place
	 * of tree storage). The basic match is PAT_MATCH_STR, but the indexation
	 * and delete functions are relative to the list management. The parse
	 * and match method are related to the corresponding fetch methods. This
	 * is very particular ACL declaration mode.
	 */
	{ "http_auth_group", NULL,       PAT_MATCH_STR, NULL,  pat_idx_list_str, pat_del_list_ptr, NULL, pat_match_auth },
	{ "method",          NULL,       PAT_MATCH_STR, pat_parse_meth, pat_idx_list_str, pat_del_list_ptr, NULL, pat_match_meth },

	{ "path",            "path",     PAT_MATCH_STR },
	{ "path_beg",        "path",     PAT_MATCH_BEG },
	{ "path_dir",        "path",     PAT_MATCH_DIR },
	{ "path_dom",        "path",     PAT_MATCH_DOM },
	{ "path_end",        "path",     PAT_MATCH_END },
	{ "path_len",        "path",     PAT_MATCH_LEN },
	{ "path_reg",        "path",     PAT_MATCH_REG },
	{ "path_sub",        "path",     PAT_MATCH_SUB },

	{ "req_ver",         "req.ver",  PAT_MATCH_STR },
	{ "resp_ver",        "res.ver",  PAT_MATCH_STR },

	{ "scook",           "res.cook", PAT_MATCH_STR },
	{ "scook_beg",       "res.cook", PAT_MATCH_BEG },
	{ "scook_dir",       "res.cook", PAT_MATCH_DIR },
	{ "scook_dom",       "res.cook", PAT_MATCH_DOM },
	{ "scook_end",       "res.cook", PAT_MATCH_END },
	{ "scook_len",       "res.cook", PAT_MATCH_LEN },
	{ "scook_reg",       "res.cook", PAT_MATCH_REG },
	{ "scook_sub",       "res.cook", PAT_MATCH_SUB },

	{ "shdr",            "res.hdr",  PAT_MATCH_STR },
	{ "shdr_beg",        "res.hdr",  PAT_MATCH_BEG },
	{ "shdr_dir",        "res.hdr",  PAT_MATCH_DIR },
	{ "shdr_dom",        "res.hdr",  PAT_MATCH_DOM },
	{ "shdr_end",        "res.hdr",  PAT_MATCH_END },
	{ "shdr_len",        "res.hdr",  PAT_MATCH_LEN },
	{ "shdr_reg",        "res.hdr",  PAT_MATCH_REG },
	{ "shdr_sub",        "res.hdr",  PAT_MATCH_SUB },

	{ "url",             "url",      PAT_MATCH_STR },
	{ "url_beg",         "url",      PAT_MATCH_BEG },
	{ "url_dir",         "url",      PAT_MATCH_DIR },
	{ "url_dom",         "url",      PAT_MATCH_DOM },
	{ "url_end",         "url",      PAT_MATCH_END },
	{ "url_len",         "url",      PAT_MATCH_LEN },
	{ "url_reg",         "url",      PAT_MATCH_REG },
	{ "url_sub",         "url",      PAT_MATCH_SUB },

	{ "urlp",            "urlp",     PAT_MATCH_STR },
	{ "urlp_beg",        "urlp",     PAT_MATCH_BEG },
	{ "urlp_dir",        "urlp",     PAT_MATCH_DIR },
	{ "urlp_dom",        "urlp",     PAT_MATCH_DOM },
	{ "urlp_end",        "urlp",     PAT_MATCH_END },
	{ "urlp_len",        "urlp",     PAT_MATCH_LEN },
	{ "urlp_reg",        "urlp",     PAT_MATCH_REG },
	{ "urlp_sub",        "urlp",     PAT_MATCH_SUB },

	{ /* END */ },
}};

INITCALL1(STG_REGISTER, acl_register_keywords, &acl_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
