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

/* pattern management function arrays */
extern char *pat_match_names[PAT_MATCH_NUM];
extern int (*pat_parse_fcts[PAT_MATCH_NUM])(const char *, struct pattern *, int, char **);
extern int (*pat_index_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pattern *, char **);
extern void (*pat_delete_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pat_ref_elt *);
extern void (*pat_prune_fcts[PAT_MATCH_NUM])(struct pattern_expr *);
extern struct pattern *(*pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern_expr *, int);
extern int pat_match_types[PAT_MATCH_NUM];

void pattern_finalize_config(void);

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
struct pattern *pattern_exec_match(struct pattern_head *head, struct sample *smp, int fill);

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
int pat_idx_tree_pfx(struct pattern_expr *expr, struct pattern *pat, char **err);

/*
 *
 * The following functions search pattern <pattern> into the pattern
 * expression <expr>. If the pattern is found, delete it. This function
 * never fails.
 *
 */
void pat_del_list_val(struct pattern_expr *expr, struct pat_ref_elt *ref);
void pat_del_tree_ip(struct pattern_expr *expr, struct pat_ref_elt *ref);
void pat_del_list_ptr(struct pattern_expr *expr, struct pat_ref_elt *ref);
void pat_del_tree_str(struct pattern_expr *expr, struct pat_ref_elt *ref);
void pat_del_list_reg(struct pattern_expr *expr, struct pat_ref_elt *ref);

/*
 *
 * The following functions clean all entries of a pattern expression and
 * reset the tree and list root.
 *
 */
void pat_prune_val(struct pattern_expr *expr);
void pat_prune_ptr(struct pattern_expr *expr);
void pat_prune_reg(struct pattern_expr *expr);

/*
 *
 * The following functions are general purpose pattern matching functions.
 *
 */


/* ignore the current line */
int pat_parse_nothing(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse an integer. It is put both in min and max. */
int pat_parse_int(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse an version. It is put both in min and max. */
int pat_parse_dotted_ver(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse a range of integers delimited by either ':' or '-'. If only one
 * integer is read, it is set as both min and max.
 */
int pat_parse_range(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse a string. It is allocated and duplicated. */
int pat_parse_str(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse a hexa binary definition. It is allocated and duplicated. */
int pat_parse_bin(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse a regex. It is allocated. */
int pat_parse_reg(const char *text, struct pattern *pattern, int mflags, char **err);

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int pat_parse_ip(const char *text, struct pattern *pattern, int mflags, char **err);

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

/*
 * pattern_ref manipulation.
 */
struct pat_ref *pat_ref_lookup(const char *reference);
struct pat_ref *pat_ref_lookupid(int unique_id);
struct pat_ref *pat_ref_new(const char *reference, const char *display, unsigned int flags);
struct pat_ref *pat_ref_newid(int unique_id, const char *display, unsigned int flags);
struct pat_ref_elt *pat_ref_find_elt(struct pat_ref *ref, const char *key);
int pat_ref_append(struct pat_ref *ref, char *pattern, char *sample, int line);
int pat_ref_add(struct pat_ref *ref, const char *pattern, const char *sample, char **err);
int pat_ref_set(struct pat_ref *ref, const char *pattern, const char *sample, char **err);
int pat_ref_set_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt, const char *value, char **err);
int pat_ref_delete(struct pat_ref *ref, const char *key);
int pat_ref_delete_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt);
void pat_ref_prune(struct pat_ref *ref);
int pat_ref_load(struct pat_ref *ref, struct pattern_expr *expr, int patflags, int soe, char **err);
void pat_ref_reload(struct pat_ref *ref, struct pat_ref *replace);


/*
 * pattern_head manipulation.
 */
void pattern_init_head(struct pattern_head *head);
void pattern_prune(struct pattern_head *head);
int pattern_read_from_file(struct pattern_head *head, unsigned int refflags, const char *filename, int patflags, int load_smp, char **err, const char *file, int line);

/*
 * pattern_expr manipulation.
 */
void pattern_init_expr(struct pattern_expr *expr);
struct pattern_expr *pattern_lookup_expr(struct pattern_head *head, struct pat_ref *ref);
struct pattern_expr *pattern_new_expr(struct pattern_head *head, struct pat_ref *ref,
                                      char **err, int *reuse);
struct sample_storage **pattern_find_smp(struct pattern_expr *expr, struct pat_ref_elt *elt);
int pattern_delete(struct pattern_expr *expr, struct pat_ref_elt *ref);


#endif
