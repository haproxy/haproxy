/*
 * include/proto/acl.h
 * This file provides interface definitions for ACL manipulation.
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
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
#include <proto/sample.h>

/*
 * FIXME: we need destructor functions too !
 */

/* Negate an acl result. This turns (ACL_MATCH_FAIL, ACL_MATCH_MISS,
 * ACL_MATCH_PASS) into (ACL_MATCH_PASS, ACL_MATCH_MISS, ACL_MATCH_FAIL).
 */
static inline enum acl_test_res acl_neg(enum acl_test_res res)
{
	return (3 >> res);
}

/* Convert an acl result to a boolean. Only ACL_MATCH_PASS returns 1. */
static inline int acl_pass(enum acl_test_res res)
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
struct acl_expr *parse_acl_expr(const char **args, char **err, struct arg_list *al, const char *file, int line);

/* Purge everything in the acl <acl>, then return <acl>. */
struct acl *prune_acl(struct acl *acl);

/* Parse an ACL with the name starting at <args>[0], and with a list of already
 * known ACLs in <acl>. If the ACL was not in the list, it will be added.
 * A pointer to that ACL is returned.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl, char **err, struct arg_list *al, const char *file, int line);

/* Purge everything in the acl_cond <cond>, then return <cond>. */
struct acl_cond *prune_acl_cond(struct acl_cond *cond);

/* Parse an ACL condition starting at <args>[0], relying on a list of already
 * known ACLs passed in <known_acl>. The new condition is returned (or NULL in
 * case of low memory). Supports multiple conditions separated by "or".
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl,
                                enum acl_cond_pol pol, char **err, struct arg_list *al,
                                const char *file, int line);

/* Builds an ACL condition starting at the if/unless keyword. The complete
 * condition is returned. NULL is returned in case of error or if the first
 * word is neither "if" nor "unless". It automatically sets the file name and
 * the line number in the condition for better error reporting, and sets the
 * HTTP initialization requirements in the proxy. If <err> is not NULL, it will
 * be set to an error message upon errors, that the caller will have to free.
 */
struct acl_cond *build_acl_cond(const char *file, int line, struct list *known_acl,
				struct proxy *px, const char **args, char **err);

/* Execute condition <cond> and return either ACL_TEST_FAIL, ACL_TEST_MISS or
 * ACL_TEST_PASS depending on the test results. ACL_TEST_MISS may only be
 * returned if <opt> does not contain SMP_OPT_FINAL, indicating that incomplete
 * data is being examined. The function automatically sets SMP_OPT_ITERATE. This
 * function only computes the condition, it does not apply the polarity required
 * by IF/UNLESS, it's up to the caller to do this.
 */
enum acl_test_res acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *sess, struct stream *strm, unsigned int opt);

/* Returns a pointer to the first ACL conflicting with usage at place <where>
 * which is one of the SMP_VAL_* bits indicating a check place, or NULL if
 * no conflict is found. Only full conflicts are detected (ACL is not usable).
 * Use the next function to check for useless keywords.
 */
const struct acl *acl_cond_conflicts(const struct acl_cond *cond, unsigned int where);

/* Returns a pointer to the first ACL and its first keyword to conflict with
 * usage at place <where> which is one of the SMP_VAL_* bits indicating a check
 * place. Returns true if a conflict is found, with <acl> and <kw> set (if non
 * null), or false if not conflict is found. The first useless keyword is
 * returned.
 */
int acl_cond_kw_conflicts(const struct acl_cond *cond, unsigned int where, struct acl const **acl, char const **kw);

/*
 * Find targets for userlist and groups in acl. Function returns the number
 * of errors or OK if everything is fine.
 */
int acl_find_targets(struct proxy *p);

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

/* initializes ACLs by resolving the sample fetch names they rely upon.
 * Returns 0 on success, otherwise an error.
 */
int init_acl();


#endif /* _PROTO_ACL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
