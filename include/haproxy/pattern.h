/*
 * include/haproxy/pattern.h
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

#ifndef _HAPROXY_PATTERN_H
#define _HAPROXY_PATTERN_H

#include <string.h>

#include <haproxy/api.h>
#include <haproxy/event_hdl.h>
#include <haproxy/pattern-t.h>
#include <haproxy/sample-t.h>

/* pattern management function arrays */
extern const char *const pat_match_names[PAT_MATCH_NUM];
extern int const pat_match_types[PAT_MATCH_NUM];

extern int (*const pat_parse_fcts[PAT_MATCH_NUM])(const char *, struct pattern *, int, char **);
extern int (*const pat_index_fcts[PAT_MATCH_NUM])(struct pattern_expr *, struct pattern *, char **);
extern void (*const pat_prune_fcts[PAT_MATCH_NUM])(struct pattern_expr *);
extern struct pattern *(*const pat_match_fcts[PAT_MATCH_NUM])(struct sample *, struct pattern_expr *, int);

/* This is the root of the list of all pattern_ref avalaibles. */
extern struct list pattern_reference;

int pattern_finalize_config(void);

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
 * to sample <smp>. The function returns NULL if the sample don't match. It returns
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
int pat_idx_list_regm(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_tree_ip(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_tree_str(struct pattern_expr *expr, struct pattern *pat, char **err);
int pat_idx_tree_pfx(struct pattern_expr *expr, struct pattern *pat, char **err);

/*
 *
 * The following function deletes all patterns related to reference pattern
 * element <elt> in pattern reference <ref>.
 *
 */
void pat_delete_gen(struct pat_ref *ref, struct pat_ref_elt *elt);

/*
 *
 * The following functions clean all entries of a pattern expression and
 * reset the tree and list root.
 *
 */
void pat_prune_gen(struct pattern_expr *expr);

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
 * The addr may either be an IPv4 or IPv6 address, or a hostname that resolves
 * to a valid IPv4 address. The mask can be provided as a number of bits, or
 * even as a dotted mask (but the latter only works for IPv4 addresses).
 * Returns 1 if OK, otherwise 0.
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

/* Check that the input IP address (IPv4 or IPv6) in <smp> matches the IP/mask
 * in pattern
 */
struct pattern *pat_match_ip(struct sample *smp, struct pattern_expr *expr, int fill);

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
struct pattern *pat_match_reg(struct sample *smp, struct pattern_expr *expr, int fill);
struct pattern *pat_match_regm(struct sample *smp, struct pattern_expr *expr, int fill);

/*
 * pattern_ref manipulation.
 */
struct pat_ref *pat_ref_lookup(const char *reference);
struct pat_ref *pat_ref_lookupid(int unique_id);
struct pat_ref *pat_ref_new(const char *reference, const char *display, unsigned int flags);
struct pat_ref *pat_ref_newid(int unique_id, const char *display, unsigned int flags);
struct pat_ref_elt *pat_ref_find_elt(struct pat_ref *ref, const char *key);
struct pat_ref_elt *pat_ref_gen_find_elt(struct pat_ref *ref, unsigned int gen_id, const char *key);
struct pat_ref_elt *pat_ref_append(struct pat_ref *ref, const char *pattern, const char *sample, int line);
struct pat_ref_elt *pat_ref_load(struct pat_ref *ref, unsigned int gen, const char *pattern, const char *sample, int line, char **err);
int pat_ref_push(struct pat_ref_elt *elt, struct pattern_expr *expr, int patflags, char **err);
int pat_ref_add(struct pat_ref *ref, const char *pattern, const char *sample, char **err);
int pat_ref_set(struct pat_ref *ref, const char *pattern, const char *sample, char **err);
int pat_ref_set_elt_duplicate(struct pat_ref *ref, struct pat_ref_elt *elt, const char *value, char **err);
int pat_ref_gen_set(struct pat_ref *ref, unsigned int gen_id, const char *key, const char *value, char **err);
int pat_ref_set_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt, const char *value, char **err);
int pat_ref_delete(struct pat_ref *ref, const char *key);
int pat_ref_gen_delete(struct pat_ref *ref, unsigned int gen_id, const char *key);
void pat_ref_delete_by_ptr(struct pat_ref *ref, struct pat_ref_elt *elt);
int pat_ref_delete_by_id(struct pat_ref *ref, struct pat_ref_elt *refelt);
int pat_ref_prune(struct pat_ref *ref);
int pat_ref_commit_elt(struct pat_ref *ref, struct pat_ref_elt *elt, char **err);
int pat_ref_purge_range(struct pat_ref *ref, uint from, uint to, int budget);

/* Create a new generation number for next pattern updates and returns it. This
 * must be used to atomically insert new patterns that will atomically replace
 * all current ones on commit. Generation numbers start at zero and are only
 * incremented and wrap at 2^32. There must not be more than 2^31-1 called
 * without a commit. The new reserved number is returned. Locking is not
 * necessary.
 */
static inline unsigned int pat_ref_newgen(struct pat_ref *ref)
{
	return HA_ATOMIC_ADD_FETCH(&ref->next_gen, 1);
}

/* Give up a previously assigned generation number. By doing this the caller
 * certifies that no element was inserted using this number, and that this
 * number might safely be reused if none was assigned since. This is convenient
 * to avoid wasting numbers in case an operation couldn't be started right
 * after a call to pat_ref_newgen(), but it is absolutely not necessary. The
 * main use case is to politely abandon an update attempt upon error just after
 * having received a number (e.g. attempting to retrieve entries from the
 * network, and failed to establish a connection). This is done atomically so
 * no locking is necessary.
 */
static inline void pat_ref_giveup(struct pat_ref *ref, unsigned int gen)
{
	HA_ATOMIC_CAS(&ref->next_gen, &gen, gen - 1);
}

/* Checks if the provided <gen> number is valid in the sense that it may
 * still be committed. Indeed, multiple gen numbers may be created in parallel,
 * but once one of them gets committed, pending generation numbers below the
 * new current one are not valid anymore (they should be recreated).
 *
 * It is not strictly mandatory to call this function under lock if the caller
 * uses this info as an opportunistic hint, otherwise, when consistency is
 * required, <ref> lock should be held as commit operation is also performed
 * under the lock.
 *
 * The function returns 1 if <gen> is still valid, and 0 otherwise
 */
static inline int pat_ref_may_commit(struct pat_ref *ref, unsigned int gen)
{
	unsigned int curr_gen = HA_ATOMIC_LOAD(&ref->curr_gen);

	if ((int)(gen - curr_gen) > 0)
		return 1;
	return 0;
}

/* Commit the whole pattern reference by updating the generation number or
 * failing in case someone else managed to do it meanwhile. While this could
 * be done using a CAS, it must instead be called with the PATREF_LOCK held in
 * order to guarantee the consistency of the generation number for all other
 * functions that rely on it. It returns zero on success, non-zero on failure
 * (technically speaking it returns the difference between the attempted
 * generation and the effective one, so that it can be used for reporting).
 */
static inline int pat_ref_commit(struct pat_ref *ref, unsigned int gen)
{
	if (pat_ref_may_commit(ref, gen)) {
		ref->curr_gen = gen;
		event_hdl_publish(&ref->e_subs, EVENT_HDL_SUB_PAT_REF_COMMIT, NULL);
	}
	return gen - ref->curr_gen;
}

/* This function purges all elements from <ref> that are older than generation
 * <oldest>. It will not purge more than <budget> entries at once, in order to
 * remain responsive. If budget is negative, no limit is applied.
 * The caller must already hold the PATREF_LOCK on <ref>. The function will
 * take the PATEXP_LOCK on all expressions of the pattern as needed. It returns
 * non-zero on completion, or zero if it had to stop before the end after
 * <budget> was depleted.
 */
static inline int pat_ref_purge_older(struct pat_ref *ref, uint oldest, int budget)
{
	return pat_ref_purge_range(ref, oldest + 1, oldest - 1, budget);
}


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
                                      int patflags, char **err, int *reuse);
struct sample_data **pattern_find_smp(struct pattern_expr *expr, struct pat_ref_elt *elt);


#endif
