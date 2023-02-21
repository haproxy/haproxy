/*
 * include/haproxy/cfgcond-t.h
 * Types for the configuration condition preprocessor
 *
 * Copyright (C) 2000-2021 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CFGCOND_T_H
#define _HAPROXY_CFGCOND_T_H

#include <haproxy/api-t.h>

/* nested if/elif/else/endif block states */
enum nested_cond_state {
	NESTED_COND_IF_TAKE,      // "if" with a true condition
	NESTED_COND_IF_DROP,      // "if" with a false condition
	NESTED_COND_IF_SKIP,      // "if" masked by an outer false condition

	NESTED_COND_ELIF_TAKE,    // "elif" with a true condition from a false one
	NESTED_COND_ELIF_DROP,    // "elif" with a false condition from a false one
	NESTED_COND_ELIF_SKIP,    // "elif" masked by an outer false condition or a previously taken if

	NESTED_COND_ELSE_TAKE,    // taken "else" after an if false condition
	NESTED_COND_ELSE_DROP,    // "else" masked by outer false condition or an if true condition
};

/* 100 levels of nested conditions should already be sufficient */
#define MAXNESTEDCONDS 100

/* supported conditional predicates for .if/.elif */
enum cond_predicate {
	CFG_PRED_NONE,                   // none
	CFG_PRED_DEFINED,                // "defined"
	CFG_PRED_FEATURE,                // "feature"
	CFG_PRED_STREQ,                  // "streq"
	CFG_PRED_STRNEQ,                 // "strneq"
	CFG_PRED_STRSTR,                 // "strstr"
	CFG_PRED_VERSION_ATLEAST,        // "version_atleast"
	CFG_PRED_VERSION_BEFORE,         // "version_before"
	CFG_PRED_OSSL_VERSION_ATLEAST,   // "openssl_version_atleast"
	CFG_PRED_OSSL_VERSION_BEFORE,    // "openssl_version_before"
	CFG_PRED_SSLLIB_NAME_STARTSWITH, // "ssllib_name_startswith"
	CFG_PRED_ENABLED,                // "enabled"
};

/* types for condition terms */
enum cfg_cond_term_type {
	CCTT_NONE = 0,
	CCTT_FALSE,
	CCTT_TRUE,
	CCTT_PRED,
	CCTT_PAREN, // '(' EXPR ')'
};

/* keyword for a condition predicate */
struct cond_pred_kw {
	const char *word;         // NULL marks the end of the list
	enum cond_predicate prd;  // one of the CFG_PRED_* above
	uint64_t arg_mask;        // mask of supported arguments (strings only)
};

/* condition term */
struct cfg_cond_term {
	enum cfg_cond_term_type type; // CCTT_*
	struct arg *args;             // arguments for predicates
	int neg;                      // 0: direct result; 1: negate
	union {
		const struct cond_pred_kw *pred; // predicate (function)
		struct cfg_cond_expr *expr;      // expression for CCTT_PAREN
	};
};

/* condition sub-expression for an AND:
 *   expr_and = <term> '&&' <expr_and>
 *            | <term>
 */
struct cfg_cond_and {
	struct cfg_cond_term *left;
	struct cfg_cond_and *right; // may be NULL
};

/* condition expression:
 *   expr = <expr_and> '||' <expr>
 *        | <expr_and>
 */
struct cfg_cond_expr {
	struct cfg_cond_and *left;
	struct cfg_cond_expr *right; // may be NULL
};

#endif /* _HAPROXY_CFGCOND_T_H */
