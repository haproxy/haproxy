/*
 * include/proto/pattern.h
 * This file provides structures and types for pattern matching.
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

#ifndef _PROTO_PATTERN_H
#define _PROTO_PATTERN_H

#include <string.h>

#include <common/config.h>
#include <common/standard.h>
#include <types/pattern.h>

/* parse the <args> with <expr> compliant parser. <pattern> is a context for
 * the current parsed acl. It must initialized at NULL:
 *
 *    struct pattern *pattern = NULL
 *    pattern_register(..., &pattern, ...);
 *
 * patflag are a lot of 'PAT_F_*' flags pattern compatible. see
 * <types/acl.h>.
 *
 * The function returns 1 if the processing is ok, return 0
 * if the parser fails, with <err> message filled.
 */
int pattern_register(struct pattern_expr *expr, const char *arg, struct sample_storage *smp, int patflags, char **err);

/* return the PAT_MATCH_* index for match name "name", or < 0 if not found */
static inline int pat_find_match_name(const char *name)
{
	int i;

	for (i = 0; i < PAT_MATCH_NUM; i++)
		if (strcmp(name, pat_match_names[i]) == 0)
			return i;
	return -1;
}

/* This function executes a pattern match on a sample. It applies pattern <expr>
 * to sample <smp>. The function returns NULL if the sample dont match. It returns
 * non-null if the sample match. If <fill> is true and the sample match, the
 * function returns the matched pattern. In many cases, this pattern can be a
 * static buffer.
 */
struct pattern *pattern_exec_match(struct pattern_expr *expr, struct sample *smp, int fill);

/*
 *
 * The following function gets "pattern", duplicate it and index it in "expr"
 *
 */
int pat_idx_list_val(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_list_ptr(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_list_str(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_list_reg(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_tree_ip(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_tree_str(struct pattern_expr *expr, struct pattern *pat, char **err);

/*
 *
 * The following functions search pattern <pattern> into the pattern
 * expression <expr>. If the pattern is found, delete it. This function
 * never fails.
 *
 */
void pat_del_list_val(struct pattern_expr *expr, struct pattern *pat);
void pat_del_tree_ip(struct pattern_expr *expr, struct pattern *pat);
void pat_del_list_ptr(struct pattern_expr *expr, struct pattern *pat);
void pat_del_tree_str(struct pattern_expr *expr, struct pattern *pat);
void pat_del_list_str(struct pattern_expr *expr, struct pattern *pat);
void pat_del_list_reg(struct pattern_expr *expr, struct pattern *pat);

/*
 *
 * The following functions are general purpose pattern matching functions.
 *
 */


/* ignore the current line */
int pat_parse_nothing(const char *text, struct pattern *pattern, char **err);

/* Parse an integer. It is put both in min and max. */
int pat_parse_int(const char *text, struct pattern *pattern, char **err);

/* Parse len like an integer, but specify expected string type */
int pat_parse_len(const char *text, struct pattern *pattern, char **err);

/* Parse an version. It is put both in min and max. */
int pat_parse_dotted_ver(const char *text, struct pattern *pattern, char **err);

/* Parse a range of integers delimited by either ':' or '-'. If only one
 * integer is read, it is set as both min and max.
 */
int pat_parse_range(const char *text, struct pattern *pattern, char **err);

/* Parse a string. It is allocated and duplicated. */
int pat_parse_str(const char *text, struct pattern *pattern, char **err);

/* Parse a hexa binary definition. It is allocated and duplicated. */
int pat_parse_bin(const char *text, struct pattern *pattern, char **err);

/* Parse a regex. It is allocated. */
int pat_parse_reg(const char *text, struct pattern *pattern, char **err);

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int pat_parse_ip(const char *text, struct pattern *pattern, char **err);

/* NB: For two strings to be identical, it is required that their lengths match */
struct pattern *pat_match_str(struct sample *smp, struct pattern_expr *expr, int fill);

/* NB: For two binary buffers to be identical, it is required that their lengths match */
struct pattern *pat_match_bin(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the length of the pattern in <test> is included between min and max */
struct pattern *pat_match_len(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the integer in <test> is included between min and max */
struct pattern *pat_match_int(struct sample *smp, struct pattern_expr *expr, int fill);

/* always return false */
struct pattern *pat_match_nothing(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the pattern matches the end of the tested string. */
struct pattern *pat_match_end(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the pattern matches the beginning of the tested string. */
struct pattern *pat_match_beg(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the pattern is included inside the tested string. */
struct pattern *pat_match_sub(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between slashes or at the beginning or end of the string. Slashes at the
 * beginning or end of the pattern are ignored.
 */
struct pattern *pat_match_dir(struct sample *smp, struct pattern_expr *expr, int fill);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between dots or at the beginning or end of the string. Dots at the beginning
 * or end of the pattern are ignored.
 */
struct pattern *pat_match_dom(struct sample *smp, struct pattern_expr *expr, int fill);

/* Check that the IPv4 address in <test> matches the IP/mask in pattern */
struct pattern *pat_match_ip(struct sample *smp, struct pattern_expr *expr, int fill);

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
struct pattern *pat_match_reg(struct sample *smp, struct pattern_expr *expr, int fill);

int pattern_read_from_file(struct pattern_expr *expr, const char *filename, int patflags, char **err);
void pattern_free(struct pattern_list *pat);
void pattern_prune_expr(struct pattern_expr *expr);
void pattern_init_expr(struct pattern_expr *expr);
int pattern_lookup(const char *args, struct pattern_expr *expr, struct pattern_list **pat_elt, struct pattern_tree **idx_elt, char **err);
int pattern_delete(const char *key, struct pattern_expr *expr, char **err);


#endif
