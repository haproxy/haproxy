/*
 * include/proto/acl.h
 * This file provides interface definitions for ACL manipulation.
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

#ifndef _PROTO_ACL_H
#define _PROTO_ACL_H

#include <common/config.h>
#include <types/acl.h>

/*
 * FIXME: we need destructor functions too !
 */

/* Negate an acl result. This turns (ACL_PAT_FAIL, ACL_PAT_MISS, ACL_PAT_PASS)
 * into (ACL_PAT_PASS, ACL_PAT_MISS, ACL_PAT_FAIL).
 */
static inline int acl_neg(int res)
{
	return (3 >> res);
}

/* Convert an acl result to a boolean. Only ACL_PAT_PASS returns 1. */
static inline int acl_pass(int res)
{
	return (res >> 1);
}

/* Return a pointer to the ACL <name> within the list starting at <head>, or
 * NULL if not found.
 */
struct acl *find_acl_by_name(const char *name, struct list *head);

/* Return a pointer to the ACL keyword <kw> within the list starting at <head>,
 * or NULL if not found. Note that if <kw> contains an opening parenthesis,
 * only the left part of it is checked.
 */
struct acl_keyword *find_acl_kw(const char *kw);

/* Parse an ACL expression starting at <args>[0], and return it.
 * Right now, the only accepted syntax is :
 * <subject> [<value>...]
 */
struct acl_expr *parse_acl_expr(const char **args);

/* Purge everything in the acl <acl>, then return <acl>. */
struct acl *prune_acl(struct acl *acl);

/* Parse an ACL with the name starting at <args>[0], and with a list of already
 * known ACLs in <acl>. If the ACL was not in the list, it will be added.
 * A pointer to that ACL is returned.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl);

/* Purge everything in the acl_cond <cond>, then return <cond>. */
struct acl_cond *prune_acl_cond(struct acl_cond *cond);

/* Parse an ACL condition starting at <args>[0], relying on a list of already
 * known ACLs passed in <known_acl>. The new condition is returned (or NULL in
 * case of low memory). Supports multiple conditions separated by "or".
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl, int pol);

/* Builds an ACL condition starting at the if/unless keyword. The complete
 * condition is returned. NULL is returned in case of error or if the first
 * word is neither "if" nor "unless". It automatically sets the file name and
 * the line number in the condition for better error reporting, and adds the
 * ACL requirements to the proxy's acl_requires.
 */
struct acl_cond *build_acl_cond(const char *file, int line, struct proxy *px, const char **args);

/* Execute condition <cond> and return either ACL_PAT_FAIL, ACL_PAT_MISS or
 * ACL_PAT_PASS depending on the test results. This function only computes the
 * condition, it does not apply the polarity required by IF/UNLESS, it's up to
 * the caller to do this.
 */
int acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *l4, void *l7, int dir);

/* Reports a pointer to the first ACL used in condition <cond> which requires
 * at least one of the USE_FLAGS in <require>. Returns NULL if none matches.
 */
struct acl *cond_find_require(const struct acl_cond *cond, unsigned int require);

/* Return a pointer to the ACL <name> within the list starting at <head>, or
 * NULL if not found.
 */
struct acl *find_acl_by_name(const char *name, struct list *head);

/*
 * Registers the ACL keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void acl_register_keywords(struct acl_kw_list *kwl);

/*
 * Unregisters the ACL keyword list <kwl> from the list of valid keywords.
 */
void acl_unregister_keywords(struct acl_kw_list *kwl);


/*
 *
 * The following functions are general purpose ACL matching functions.
 *
 */


/* ignore the current line */
int acl_parse_nothing(const char **text, struct acl_pattern *pattern, int *opaque);

/* NB: For two strings to be identical, it is required that their lengths match */
int acl_match_str(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the integer in <test> is included between min and max */
int acl_match_int(struct acl_test *test, struct acl_pattern *pattern);

/* Parse an integer. It is put both in min and max. */
int acl_parse_int(const char **text, struct acl_pattern *pattern, int *opaque);

/* Parse an version. It is put both in min and max. */
int acl_parse_dotted_ver(const char **text, struct acl_pattern *pattern, int *opaque);

/* Parse a range of integers delimited by either ':' or '-'. If only one
 * integer is read, it is set as both min and max.
 */
int acl_parse_range(const char **text, struct acl_pattern *pattern, int *opaque);

/* Parse a string. It is allocated and duplicated. */
int acl_parse_str(const char **text, struct acl_pattern *pattern, int *opaque);

/* Parse a regex. It is allocated. */
int acl_parse_reg(const char **text, struct acl_pattern *pattern, int *opaque);

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int acl_parse_ip(const char **text, struct acl_pattern *pattern, int *opaque);

/* always fake a data retrieval */
int acl_fetch_nothing(struct proxy *px, struct session *l4, void *l7, int dir,
		      struct acl_expr *expr, struct acl_test *test);

/* always return false */
int acl_match_nothing(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the pattern matches the end of the tested string. */
int acl_match_end(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the pattern matches the beginning of the tested string. */
int acl_match_beg(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string. */
int acl_match_sub(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between slashes or at the beginning or end of the string. Slashes at the
 * beginning or end of the pattern are ignored.
 */
int acl_match_dir(struct acl_test *test, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between dots or at the beginning or end of the string. Dots at the beginning
 * or end of the pattern are ignored.
 */
int acl_match_dom(struct acl_test *test, struct acl_pattern *pattern);

/* Check that the IPv4 address in <test> matches the IP/mask in pattern */
int acl_match_ip(struct acl_test *test, struct acl_pattern *pattern);

/* Executes a regex. It needs to change the data. If it is marked READ_ONLY
 * then it will be allocated and duplicated in place so that others may use
 * it later on. Note that this is embarrassing because we always try to avoid
 * allocating memory at run time.
 */
int acl_match_reg(struct acl_test *test, struct acl_pattern *pattern);

#endif /* _PROTO_ACL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
