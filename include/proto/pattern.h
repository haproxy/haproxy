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

/* parse the <text> with <expr> compliant parser. <pattern> is a context for
 * the current parsed acl. It must initialized at NULL:
 *
 *    struct acl_pattern *pattern = NULL
 *    acl_register_pattern(..., &pattern, ...);
 *
 * patflag are a combination of 'ACL_PAT_F_*' flags pattern compatible. see
 * <types/acl.h>.
 *
 * The function returns 1 if the processing is ok, return -1 if the parser
 * fails, with <err> message filled. It returns -2 in "out of memory"
 * error case.
 */
int acl_register_pattern(struct acl_expr *expr, char *text, struct sample_storage *smp, struct acl_pattern **pattern, int patflags, char **err);

/* This function executes a pattern match on a sample. It applies pattern <expr>
 * to sample <smp>. If <sample> is not NULL, a pointer to an optional sample
 * associated to the matching patterned will be put there. The function returns
 * ACL_PAT_FAIL, ACL_PAT_MISS or ACL_PAT_PASS.
 */
inline int acl_exec_match(struct acl_expr *expr, struct sample *smp, struct sample_storage **sample);

/*
 *
 * The following functions are general purpose pattern matching functions.
 *
 */


/* ignore the current line */
int acl_parse_nothing(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* NB: For two strings to be identical, it is required that their lengths match */
int acl_match_str(struct sample *smp, struct acl_pattern *pattern);

/* NB: For two binary buffers to be identical, it is required that their lengths match */
int acl_match_bin(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the length of the pattern in <test> is included between min and max */
int acl_match_len(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the integer in <test> is included between min and max */
int acl_match_int(struct sample *smp, struct acl_pattern *pattern);

/* Parse an integer. It is put both in min and max. */
int acl_parse_int(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse an version. It is put both in min and max. */
int acl_parse_dotted_ver(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse a range of integers delimited by either ':' or '-'. If only one
 * integer is read, it is set as both min and max.
 */
int acl_parse_range(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse a string. It is allocated and duplicated. */
int acl_parse_str(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse a hexa binary definition. It is allocated and duplicated. */
int acl_parse_bin(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse and concatenate strings into one. It is allocated and duplicated. */
int acl_parse_strcat(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse a regex. It is allocated. */
int acl_parse_reg(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int acl_parse_ip(const char **text, struct acl_pattern *pattern, struct sample_storage *smp, int *opaque, char **err);

/* always return false */
int acl_match_nothing(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the pattern matches the end of the tested string. */
int acl_match_end(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the pattern matches the beginning of the tested string. */
int acl_match_beg(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string. */
int acl_match_sub(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between slashes or at the beginning or end of the string. Slashes at the
 * beginning or end of the pattern are ignored.
 */
int acl_match_dir(struct sample *smp, struct acl_pattern *pattern);

/* Checks that the pattern is included inside the tested string, but enclosed
 * between dots or at the beginning or end of the string. Dots at the beginning
 * or end of the pattern are ignored.
 */
int acl_match_dom(struct sample *smp, struct acl_pattern *pattern);

/* Check that the IPv4 address in <test> matches the IP/mask in pattern */
int acl_match_ip(struct sample *smp, struct acl_pattern *pattern);

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
int acl_match_reg(struct sample *smp, struct acl_pattern *pattern);

int acl_read_patterns_from_file(struct acl_expr *expr, const char *filename, int patflags, char **err);
void free_pattern(struct acl_pattern *pat);
void free_pattern_list(struct list *head);
void free_pattern_tree(struct eb_root *root);

#endif
