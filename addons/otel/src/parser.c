/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


#ifdef OTELC_DBG_MEM
static struct otelc_dbg_mem_data dbg_mem_data[1000000];
static struct otelc_dbg_mem      dbg_mem;
#endif

static struct flt_otel_conf       *flt_otel_current_config = NULL;
static struct flt_otel_conf_instr *flt_otel_current_instr = NULL;
static struct flt_otel_conf_group *flt_otel_current_group = NULL;
static struct flt_otel_conf_scope *flt_otel_current_scope = NULL;
static struct flt_otel_conf_span  *flt_otel_current_span = NULL;


/***
 * NAME
 *   flt_otel_parse_strdup - string duplication with error handling
 *
 * SYNOPSIS
 *   static int flt_otel_parse_strdup(char **dst, size_t *dst_len, const char *src, char **err, const char *err_msg)
 *
 * ARGUMENTS
 *   dst     - pointer to the destination string pointer
 *   dst_len - optional pointer to store the duplicated string length
 *   src     - source string to duplicate
 *   err     - indirect pointer to error message string
 *   err_msg - context label used in error messages
 *
 * DESCRIPTION
 *   Duplicates the string <src> into <*dst> with error handling.  Optionally
 *   stores the string length in <dst_len>.  On failure, an error message is
 *   formatted using <err_msg> as context.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_strdup(char **dst, size_t *dst_len, const char *src, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	OTELC_FUNC("%p:%p, %p, %p, %p:%p, \"%s\"", OTELC_DPTR_ARGS(dst), dst_len, src, OTELC_DPTR_ARGS(err), OTELC_STR_ARG(err_msg));

	/* dst_len is not set if the string has not been copied. */
	*dst = OTELC_STRDUP(src);
	if (*dst == NULL)
		FLT_OTEL_PARSE_ERR(err, "'%s' : out of memory", err_msg);
	else if (dst_len != NULL)
		*dst_len = strlen(*dst);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_keyword - keyword argument parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_keyword(char **ptr, char **args, int cur_arg, int pos, char **err, const char *err_msg)
 *
 * ARGUMENTS
 *   ptr     - pointer to the destination string pointer
 *   args    - configuration line arguments array
 *   cur_arg - current argument index for error reporting
 *   pos     - position of the keyword in <args>
 *   err     - indirect pointer to error message string
 *   err_msg - context label used in error messages
 *
 * DESCRIPTION
 *   Parses a single keyword argument from the configuration line.  Checks
 *   that the keyword has not already been set and that a value is present
 *   at position <pos> + 1 in <args>.  The value is duplicated via
 *   flt_otel_parse_strdup() into <*ptr>.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_keyword(char **ptr, char **args, int cur_arg, int pos, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	OTELC_FUNC("%p:%p, %p, %d, %d, %p:%p, \"%s\"", OTELC_DPTR_ARGS(ptr), args, cur_arg, pos, OTELC_DPTR_ARGS(err), OTELC_STR_ARG(err_msg));

	/* Reject duplicate keyword assignments. */
	if (*ptr != NULL) {
		if (cur_arg == pos)
			FLT_OTEL_PARSE_ERR(err, FLT_OTEL_FMT_TYPE "%s already set", err_msg);
		else
			FLT_OTEL_PARSE_ERR(err, "'%s' : %s already set", args[cur_arg], err_msg);
	}
	else if (!FLT_OTEL_ARG_ISVALID(pos + 1)) {
		if (cur_arg == pos)
			FLT_OTEL_PARSE_ERR(err, FLT_OTEL_FMT_TYPE "no %s set", err_msg);
		else
			FLT_OTEL_PARSE_ERR(err, "'%s' : no %s set", args[cur_arg], err_msg);
	}
	else {
		retval = flt_otel_parse_strdup(ptr, NULL, args[pos + 1], err, args[cur_arg]);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_invalid_char - name character validation
 *
 * SYNOPSIS
 *   static const char *flt_otel_parse_invalid_char(const char *name, int type)
 *
 * ARGUMENTS
 *   name - string to validate
 *   type - validation type selector
 *
 * DESCRIPTION
 *   Validates characters in a <name> string according to the specified <type>.
 *   Uses HAProxy's invalid_char() for identifiers, invalid_domainchar() for
 *   domains, invalid_prefix_char() for context prefixes, and a custom
 *   alphanumeric check for variables.
 *
 * RETURN VALUE
 *   Returns a pointer to the first invalid character in <name>,
 *   or NULL if all characters are valid.
 */
static const char *flt_otel_parse_invalid_char(const char *name, int type)
{
	const char *retptr = NULL;

	OTELC_FUNC("\"%s\", %d", OTELC_STR_ARG(name), type);

	if (!OTELC_STR_IS_VALID(name))
		OTELC_RETURN_EX(retptr, const char *, "%p");

	/* Dispatch to the appropriate character validation function. */
	if (type == FLT_OTEL_PARSE_INVALID_CHAR) {
		retptr = invalid_char(name);
	}
	else if (type == FLT_OTEL_PARSE_INVALID_DOM) {
		retptr = invalid_domainchar(name);
	}
	else if (type == FLT_OTEL_PARSE_INVALID_CTX) {
		retptr = invalid_prefix_char(name);
	}
	else if (type == FLT_OTEL_PARSE_INVALID_VAR) {
		retptr = name;

		/*
		 * Allowed characters are letters, numbers and '_', the first
		 * character in the string must not be a number.
		 */
		if (!isdigit(*retptr))
			for (++retptr; (*retptr == '_') || isalnum(*retptr); retptr++);

		if (*retptr == '\0')
			retptr = NULL;
	}

	OTELC_RETURN_EX(retptr, const char *, "%p");
}


/***
 * NAME
 *   flt_otel_parse_cfg_check - configuration keyword validation
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_check(const char *file, int line, char **args, const void *id, const struct flt_otel_parse_data *parse_data, size_t parse_data_size, const struct flt_otel_parse_data **pdata, char **err)
 *
 * ARGUMENTS
 *   file            - configuration file path
 *   line            - configuration file line number
 *   args            - configuration line arguments array
 *   id              - parent section identifier
 *   parse_data      - keyword definition table
 *   parse_data_size - number of entries in <parse_data>
 *   pdata           - output pointer to the matched keyword entry
 *   err             - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Common validation for configuration keywords.  Looks up <args[0]> in the
 *   <parse_data> table, checks argument count bounds, validates the first
 *   argument's characters according to the keyword's check_name type, and
 *   verifies that the parent section ID is set when required.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_check(const char *file, int line, char **args, const void *id, const struct flt_otel_parse_data *parse_data, size_t parse_data_size, const struct flt_otel_parse_data **pdata, char **err)
{
	int i, argc, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p, %zu, %p:%p, %p:%p", OTELC_STR_ARG(file), line, args, id, parse_data, parse_data_size, OTELC_DPTR_ARGS(pdata), OTELC_DPTR_ARGS(err));

	FLT_OTEL_ARGS_DUMP();

	*pdata = NULL;

	/* First check here if args[0] is the correct keyword. */
	for (i = 0; (*pdata == NULL) && (i < parse_data_size); i++)
		if (FLT_OTEL_PARSE_KEYWORD(0, parse_data[i].name))
			*pdata = parse_data + i;

	if (*pdata == NULL)
		FLT_OTEL_PARSE_ERR(err, "'%s' : unknown keyword", args[0]);
	else
		argc = flt_otel_args_count((const char **)args);

	if ((retval & ERR_CODE) || (id == NULL))
		/* Do nothing. */;
	else if ((id != flt_otel_current_instr) && (flt_otel_current_config->instr == NULL))
		FLT_OTEL_PARSE_ERR(err, "instrumentation not defined");

	/*
	 * Checking that fewer arguments are specified in the configuration
	 * line than is required.
	 */
	if (!(retval & ERR_CODE))
		if (argc < (*pdata)->args_min)
			FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[0], (*pdata)->name, (*pdata)->usage);

	/*
	 * Checking that more arguments are specified in the configuration
	 * line than the maximum allowed.
	 */
	if (!(retval & ERR_CODE) && ((*pdata)->args_max > 0))
		if (argc > (*pdata)->args_max)
			FLT_OTEL_PARSE_ERR(err, "'%s' : too many arguments (use '%s%s')", args[0], (*pdata)->name, (*pdata)->usage);

	/* Checking that the first argument has only allowed characters. */
	if (!(retval & ERR_CODE) && ((*pdata)->check_name != FLT_OTEL_PARSE_INVALID_NONE)) {
		const char *ic;

		ic = flt_otel_parse_invalid_char(args[1], (*pdata)->check_name);
		if (ic != NULL)
			FLT_OTEL_PARSE_ERR(err, "%s '%s' : invalid character '%c'", args[0], args[1], *ic);
	}

	/* Checking that the data group name is defined. */
	if (!(retval & ERR_CODE) && (*pdata)->flag_check_id && (id == NULL))
		FLT_OTEL_PARSE_ERR(err, "'%s' : %s ID not set (use '%s%s')", args[0], parse_data[1].name, parse_data[1].name, parse_data[1].usage);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_sample_expr - sample expression parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_sample_expr(const char *file, int line, char **args, int *idx, struct list *head, char **err)
 *
 * ARGUMENTS
 *   file - configuration file path
 *   line - configuration file line number
 *   args - configuration line arguments array
 *   idx  - pointer to the current position in <args>
 *   head - list head for parsed sample expressions
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses a single HAProxy sample expression at position <*idx> in <args>.
 *   Creates a conf_sample_expr structure and calls sample_parse_expr() to
 *   compile the expression.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_sample_expr(const char *file, int line, char **args, int *idx, struct list *head, char **err)
{
	struct flt_otel_conf_sample_expr *expr;
	int                             retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p, %p:%p", OTELC_STR_ARG(file), line, args, idx, head, OTELC_DPTR_ARGS(err));

	expr = flt_otel_conf_sample_expr_init(args[*idx], line, head, err);
	if (expr != NULL) {
		expr->expr = sample_parse_expr(args, idx, file, line, err, &(flt_otel_current_config->proxy->conf.args), NULL);
		if (expr->expr != NULL)
			OTELC_DBG(DEBUG, "sample expression '%s' added", expr->fmt_expr);
		else
			retval |= ERR_ABORT | ERR_ALERT;
	} else {
		retval |= ERR_ABORT | ERR_ALERT;
	}

	if (retval & ERR_CODE)
		flt_otel_conf_sample_expr_free(&expr);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_sample - sample definition parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_sample(const char *file, int line, char **args, int idx, int n, const struct otelc_value *extra, struct list *head, char **err)
 *
 * ARGUMENTS
 *   file  - configuration file path
 *   line  - configuration file line number
 *   args  - configuration line arguments array
 *   idx   - args[] position where the sample value starts
 *   n     - maximum number of sample expressions to parse (0 means unlimited)
 *   extra - optional extra data (event name or status code)
 *   head  - list head for parsed sample definitions
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses a complete sample definition starting at index <idx> in the
 *   <args> array.  A new conf_sample structure is allocated and initialized
 *   via flt_otel_conf_sample_init_ex() with the optional <extra> data (an
 *   event name or a status code), then the sample expressions are parsed.
 *
 *   When <args>[<idx>] contains the "%[" sequence, the argument is parsed
 *   as a log-format string via parse_logformat_string(): the lf_used flag
 *   is set and the result is stored in the lf_expr member while the exprs
 *   list remains empty.  Otherwise the arguments are treated as bare sample
 *   expressions: the proxy configuration context is set and the function
 *   calls flt_otel_parse_cfg_sample_expr() in a loop to populate exprs.
 *
 *   When <n> is 0 all remaining valid arguments are consumed; otherwise at
 *   most <n> expressions are parsed.  On error the allocated conf_sample
 *   structure is freed before returning.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success, or a combination of ERR_* flags
 *   if an error is encountered.
 */
static int flt_otel_parse_cfg_sample(const char *file, int line, char **args, int idx, int n, const struct otelc_value *extra, struct list *head, char **err)
{
	struct flt_otel_conf_sample *sample;
	int                          retval = ERR_NONE;
	int                          count = 0;

	OTELC_FUNC("\"%s\", %d, %p, %d, %d, %p, %p, %p:%p", OTELC_STR_ARG(file), line, args, idx, n, extra, head, OTELC_DPTR_ARGS(err));

	sample = flt_otel_conf_sample_init_ex((const char **)args, idx, n, extra, line, head, err);
	if (sample == NULL)
		FLT_OTEL_PARSE_ERR(err, "'%s' : out of memory", args[0]);

	if (retval & ERR_CODE) {
		/* Do nothing. */
	}
	else if (strstr(args[idx], "%[") != NULL) {
		/*
		 * Log-format path: parse the single argument as a log-format
		 * string into the sample structure.
		 */
		sample->lf_used = 1;

		if (parse_logformat_string(args[idx], flt_otel_current_config->proxy, &(sample->lf_expr), LOG_OPT_HTTP, SMP_VAL_FE_LOG_END, err) == 0)
			retval |= ERR_ABORT | ERR_ALERT;
		else
			OTELC_DBG(DEBUG, "sample '%s' -> log-format '%s' added", sample->key, sample->fmt_string);
	}
	else {
		/*
		 * Bare sample expression path.
		 */
		flt_otel_current_config->proxy->conf.args.ctx  = ARGC_OTEL;
		flt_otel_current_config->proxy->conf.args.file = file;
		flt_otel_current_config->proxy->conf.args.line = line;

		while (!(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(idx) && ((n == 0) || (count < n))) {
			retval = flt_otel_parse_cfg_sample_expr(file, line, args, &idx, &(sample->exprs), err);
			if (!(retval & ERR_CODE))
				count++;
		}

		flt_otel_current_config->proxy->conf.args.file = NULL;
		flt_otel_current_config->proxy->conf.args.line = 0;

		OTELC_DBG(DEBUG, "sample '%s' -> '%s' added, (%d %d)", sample->key, sample->fmt_string, sample->num_exprs, count);
	}

	if (retval & ERR_CODE)
		flt_otel_conf_sample_free(&sample);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_str - string list parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_str(const char *file, int line, char **args, struct list *head, char **err)
 *
 * ARGUMENTS
 *   file - configuration file path
 *   line - configuration file line number
 *   args - configuration line arguments array
 *   head - list head for parsed string entries
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses one or more string arguments into a conf_str list.  All arguments
 *   starting from index 1 are added to <head>.  Used for the "finish" keyword.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_str(const char *file, int line, char **args, struct list *head, char **err)
{
	int i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p:%p", OTELC_STR_ARG(file), line, args, head, OTELC_DPTR_ARGS(err));

	for (i = 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++)
		if (flt_otel_conf_str_init(args[i], line, head, err) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_file - file path argument parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_file(char **ptr, const char *file, int line, char **args, char **err, const char *err_msg)
 *
 * ARGUMENTS
 *   ptr     - pointer to the destination file path string pointer
 *   file    - configuration file path
 *   line    - configuration file line number
 *   args    - configuration line arguments array
 *   err     - indirect pointer to error message string
 *   err_msg - context label used in error messages
 *
 * DESCRIPTION
 *   Parses and validates a file path argument.  Checks that the argument is
 *   present, that no extra arguments follow, and that the file exists and is
 *   readable.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_file(char **ptr, const char *file, int line, char **args, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	OTELC_FUNC("%p:%p, \"%s\", %d, %p, %p:%p, \"%s\"", OTELC_DPTR_ARGS(ptr), OTELC_STR_ARG(file), line, args, OTELC_DPTR_ARGS(err), err_msg);

	if (!FLT_OTEL_ARG_ISVALID(1))
		FLT_OTEL_PARSE_ERR(err, "'%s' : no %s specified", flt_otel_current_instr->id, err_msg);
	else if (alertif_too_many_args(1, file, line, args, &retval))
		retval |= ERR_ABORT | ERR_ALERT;
	else if (access(args[1], R_OK) == -1)
		FLT_OTEL_PARSE_ERR(err, "'%s' : %s", args[1], strerror(errno));
	else
		retval = flt_otel_parse_keyword(ptr, args, 0, 0, err, err_msg);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_check_scope - configuration scope filter
 *
 * SYNOPSIS
 *   static bool flt_otel_parse_check_scope(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Checks whether the current configuration parsing is within the correct
 *   HAProxy cfg_scope filter.  When cfg_scope is set and does not match the
 *   current filter ID, the configuration line is skipped.
 *
 * RETURN VALUE
 *   Returns TRUE in case the configuration is not in the currently
 *   defined scope, FALSE otherwise.
 */
static bool flt_otel_parse_check_scope(void)
{
	bool retval = 0;

	if ((cfg_scope != NULL) && (flt_otel_current_config->id != NULL) && (strcmp(flt_otel_current_config->id, cfg_scope) != 0)) {
		OTELC_DBG(INFO, "cfg_scope: '%s', id: '%s'", cfg_scope, flt_otel_current_config->id);

		retval = 1;
	}

	return retval;
}


/***
 * NAME
 *   flt_otel_parse_cfg_instr - otel-instrumentation section parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_instr(const char *file, int line, char **args, int kw_mod)
 *
 * ARGUMENTS
 *   file   - configuration file path
 *   line   - configuration file line number
 *   args   - configuration line arguments array
 *   kw_mod - keyword modifier flags (e.g. KWM_NO)
 *
 * DESCRIPTION
 *   Section parser for the otel-instrumentation configuration block.  Handles
 *   keywords: instrumentation ID, log, config, groups, scopes, acl, rate-limit,
 *   option (disabled/hard-errors/nolognorm), and debug-level.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_instr(const char *file, int line, char **args, int kw_mod)
{
#define FLT_OTEL_PARSE_INSTR_DEF(a,b,c,d,e,f,g)   { FLT_OTEL_PARSE_INSTR_##a, b, FLT_OTEL_PARSE_INVALID_##c, d, e, f, g },
	static const struct flt_otel_parse_data  parse_data[] = { FLT_OTEL_PARSE_INSTR_DEFINES };
#undef FLT_OTEL_PARSE_INSTR_DEF
	const struct flt_otel_parse_data        *pdata = NULL;
	char                                    *err = NULL, *err_log = NULL;
	int                                      i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, 0x%08x", OTELC_STR_ARG(file), line, args, kw_mod);

	if (flt_otel_parse_check_scope())
		OTELC_RETURN_INT(retval);

	/* Validate and identify the instrumentation keyword. */
	retval = flt_otel_parse_cfg_check(file, line, args, flt_otel_current_instr, parse_data, OTELC_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OTEL_PARSE_IFERR_ALERT();

		OTELC_RETURN_INT(retval);
	}

	/* Handle keyword-specific instrumentation configuration. */
	if (pdata->keyword == FLT_OTEL_PARSE_INSTR_ID) {
		if (flt_otel_current_config->instr != NULL) {
			FLT_OTEL_PARSE_ERR(&err, "'%s' : instrumentation can be defined only once", args[1]);
		} else {
			flt_otel_current_instr = flt_otel_conf_instr_init(args[1], line, NULL, &err);
			if (flt_otel_current_instr == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
		}
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_LOG) {
		if (parse_logger(args, &(flt_otel_current_instr->proxy_log.loggers), kw_mod == KWM_NO, file, line, &err_log) == 0) {
			FLT_OTEL_PARSE_ERR(&err, "'%s %s ...' : %s", args[0], args[1], err_log);
			OTELC_SFREE_CLEAR(err_log);
		} else {
			flt_otel_current_instr->logging |= FLT_OTEL_LOGGING_ON;
		}
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_CONFIG) {
		retval = flt_otel_parse_cfg_file(&(flt_otel_current_instr->config), file, line, args, &err, "configuration file");
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_GROUPS) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++)
			if (flt_otel_conf_ph_init(args[i], line, &(flt_otel_current_instr->ph_groups), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_SCOPES) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++)
			if (flt_otel_conf_ph_init(args[i], line, &(flt_otel_current_instr->ph_scopes), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_ACL) {
		if (FLT_OTEL_PARSE_KEYWORD(1, "or"))
			FLT_OTEL_PARSE_ERR(&err, "'%s %s ...' : invalid ACL name", args[0], args[1]);
		else if (parse_acl((const char **)args + 1, &(flt_otel_current_instr->acls), &err, &(flt_otel_current_config->proxy->conf.args), file, line) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_RATE_LIMIT) {
		double value;

		if (flt_otel_strtod(args[1], &value, 0.0, 100.0, &err))
			flt_otel_current_instr->rate_limit = FLT_OTEL_FLOAT_U32(value);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_OPTION) {
		if (FLT_OTEL_PARSE_KEYWORD(1, FLT_OTEL_PARSE_OPTION_DISABLED)) {
			flt_otel_current_instr->flag_disabled = (kw_mod == KWM_NO) ? 0 : 1;
		}
		else if (FLT_OTEL_PARSE_KEYWORD(1, FLT_OTEL_PARSE_OPTION_HARDERR)) {
			flt_otel_current_instr->flag_harderr = (kw_mod == KWM_NO) ? 0 : 1;
		}
		else if (FLT_OTEL_PARSE_KEYWORD(1, FLT_OTEL_PARSE_OPTION_NOLOGNORM)) {
			if (kw_mod == KWM_NO)
				flt_otel_current_instr->logging &= ~FLT_OTEL_LOGGING_NOLOGNORM;
			else
				flt_otel_current_instr->logging |= FLT_OTEL_LOGGING_NOLOGNORM;
		}
		else
			FLT_OTEL_PARSE_ERR(&err, "'%s' : unknown option '%s'", args[0], args[1]);
	}
#ifdef DEBUG_OTEL
	else if (pdata->keyword == FLT_OTEL_PARSE_INSTR_DEBUG_LEVEL) {
		int64_t value;

		if (flt_otel_strtoll(args[1], &value, 0, OTELC_DBG_LEVEL_MASK, &err))
			otelc_dbg_level = value;
	}
#else
	else {
		FLT_OTEL_PARSE_WARNING("'%s' : keyword ignored", file, line, args[0]);
	}
#endif

	FLT_OTEL_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_otel_current_instr != NULL))
		flt_otel_conf_instr_free(&flt_otel_current_instr);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_post_parse_cfg_instr - otel-instrumentation post-parse check
 *
 * SYNOPSIS
 *   static int flt_otel_post_parse_cfg_instr(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Post-parse callback for the otel-instrumentation section.  Links the parsed
 *   instrumentation structure to the filter configuration and verifies that a
 *   configuration file path is specified.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_post_parse_cfg_instr(void)
{
	int retval = ERR_NONE;

	OTELC_FUNC("");

	if (flt_otel_current_instr == NULL)
		OTELC_RETURN_INT(retval);

	flt_otel_current_config->instr = flt_otel_current_instr;

	if (flt_otel_current_instr->id == NULL)
		OTELC_RETURN_INT(retval);

	if (flt_otel_current_instr->config == NULL)
		FLT_OTEL_POST_PARSE_ALERT("instrumentation '%s' has no configuration file specified", flt_otel_current_instr->cfg_line, flt_otel_current_instr->id);

	flt_otel_current_instr = NULL;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_group - otel-group section parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_group(const char *file, int line, char **args, int kw_mod)
 *
 * ARGUMENTS
 *   file   - configuration file path
 *   line   - configuration file line number
 *   args   - configuration line arguments array
 *   kw_mod - keyword modifier flags (e.g. KWM_NO)
 *
 * DESCRIPTION
 *   Section parser for the otel-group configuration block.  Handles keywords:
 *   group ID and scopes.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_group(const char *file, int line, char **args, int kw_mod)
{
#define FLT_OTEL_PARSE_GROUP_DEF(a,b,c,d,e,f,g)   { FLT_OTEL_PARSE_GROUP_##a, b, FLT_OTEL_PARSE_INVALID_##c, d, e, f, g },
	static const struct flt_otel_parse_data  parse_data[] = { FLT_OTEL_PARSE_GROUP_DEFINES };
#undef FLT_OTEL_PARSE_GROUP_DEF
	const struct flt_otel_parse_data        *pdata = NULL;
	char                                    *err = NULL;
	int                                      i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, 0x%08x", OTELC_STR_ARG(file), line, args, kw_mod);

	if (flt_otel_parse_check_scope())
		OTELC_RETURN_INT(retval);

	/* Validate and identify the group keyword. */
	retval = flt_otel_parse_cfg_check(file, line, args, flt_otel_current_group, parse_data, OTELC_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OTEL_PARSE_IFERR_ALERT();

		OTELC_RETURN_INT(retval);
	}

	/* Handle keyword-specific group configuration. */
	if (pdata->keyword == FLT_OTEL_PARSE_GROUP_ID) {
		flt_otel_current_group = flt_otel_conf_group_init(args[1], line, &(flt_otel_current_config->groups), &err);
		if (flt_otel_current_group == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_GROUP_SCOPES) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++)
			if (flt_otel_conf_ph_init(args[i], line, &(flt_otel_current_group->ph_scopes), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}

	FLT_OTEL_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_otel_current_group != NULL))
		flt_otel_conf_group_free(&flt_otel_current_group);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_post_parse_cfg_group - otel-group post-parse check
 *
 * SYNOPSIS
 *   static int flt_otel_post_parse_cfg_group(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Post-parse callback for the otel-group section.  Verifies that at least one
 *   scope is defined in the group.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_post_parse_cfg_group(void)
{
	int retval = ERR_NONE;

	OTELC_FUNC("");

	if (flt_otel_current_group == NULL)
		OTELC_RETURN_INT(retval);

	/* Check that the group has at least one scope defined. */
	if (LIST_ISEMPTY(&(flt_otel_current_group->ph_scopes)))
		FLT_OTEL_POST_PARSE_ALERT("group '%s' has no defined scope(s)", flt_otel_current_group->cfg_line, flt_otel_current_group->id);

	flt_otel_current_group = NULL;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_scope_ctx - context storage type parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_scope_ctx(char **args, int cur_arg, char **err)
 *
 * ARGUMENTS
 *   args    - configuration line arguments array
 *   cur_arg - index of the storage type argument in <args>
 *   err     - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the context storage type argument for inject/extract keywords.
 *   Accepts "use-headers" or (when USE_OTEL_VARS is defined) "use-vars".
 *   Both types may be used simultaneously on the same span.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_scope_ctx(char **args, int cur_arg, char **err)
{
	uint8_t flags = 0;
	int     retval = ERR_NONE;

	OTELC_FUNC("%p, %d, %p:%p", args, cur_arg, OTELC_DPTR_ARGS(err));

	if (FLT_OTEL_PARSE_KEYWORD(cur_arg, FLT_OTEL_PARSE_CTX_USE_HEADERS))
		flags = FLT_OTEL_CTX_USE_HEADERS;
#ifdef USE_OTEL_VARS
	else if (FLT_OTEL_PARSE_KEYWORD(cur_arg, FLT_OTEL_PARSE_CTX_USE_VARS))
		flags = FLT_OTEL_CTX_USE_VARS;
#endif
	else
		FLT_OTEL_PARSE_ERR(err, "'%s' : invalid context storage type", args[0]);

	if (flags == 0)
		/* Do nothing. */;
	else if (flt_otel_current_span->ctx_flags & flags)
		FLT_OTEL_PARSE_ERR(err, "'%s' : %s already used", args[0], args[cur_arg]);
	else
		flt_otel_current_span->ctx_flags |= flags;

	OTELC_DBG(NOTICE, "ctx_flags: 0x%02hhx (0x%02hhx)", flt_otel_current_span->ctx_flags, flags);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_acl - ACL condition builder
 *
 * SYNOPSIS
 *   static struct acl_cond *flt_otel_parse_acl(const char *file, int line, struct proxy *px, const char **args, char **err, struct list *head, ...)
 *
 * ARGUMENTS
 *   file - configuration file path
 *   line - configuration file line number
 *   px   - proxy instance for ACL resolution
 *   args - condition arguments (if/unless followed by ACL names)
 *   err  - indirect pointer to error message string
 *   head - first ACL list head to search
 *
 * DESCRIPTION
 *   Builds an ACL condition by trying multiple ACL lists in order.  The
 *   variadic arguments provide a sequence of ACL list heads to search; the
 *   first successful build_acl_cond() result is returned.
 *
 * RETURN VALUE
 *   Returns a pointer to the built ACL condition, or NULL if no condition could
 *   be built from any of the provided lists.
 */
static struct acl_cond *flt_otel_parse_acl(const char *file, int line, struct proxy *px, const char **args, char **err, struct list *head, ...)
{
	va_list          ap;
	int              n = 0;
	struct acl_cond *retptr = NULL;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p:%p, %p, ...", OTELC_STR_ARG(file), line, px, args, OTELC_DPTR_ARGS(err), head);

	/* Try each ACL list in order until a condition is built. */
	for (va_start(ap, head); (retptr == NULL) && (head != NULL); head = va_arg(ap, typeof(head)), n++) {
		retptr = build_acl_cond(file, line, head, px, args, (n == 0) ? err : NULL);
		if (retptr != NULL)
			OTELC_DBG(NOTICE, "ACL build done, using list %p %d", head, n);
	}
	va_end(ap);

	if ((retptr != NULL) && (err != NULL))
		ha_free(err);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_parse_bounds - histogram boundary string parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_bounds(const char *str, double **bounds, size_t *bounds_num, char **err, const char *err_msg)
 *
 * ARGUMENTS
 *   str        - space-separated numeric boundary string
 *   bounds     - pointer to the destination boundary array
 *   bounds_num - pointer to store the number of boundaries
 *   err        - indirect pointer to error message string
 *   err_msg    - context label used in error messages
 *
 * DESCRIPTION
 *   Parses a space-separated string of numbers into a dynamically allocated
 *   array of doubles suitable for the meter add_view API.  The string is
 *   duplicated internally and tokenized with strtok().  Each token is
 *   converted with flt_otel_strtod().  The values are sorted internally.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_bounds(const char *str, double **bounds, size_t *bounds_num, char **err, const char *err_msg)
{
	char   *buffer, *token, *lasts;
	size_t  bounds_len = 0, bounds_size = 8;
	double  value, *ptr;
	int     retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %p, %p, %p:%p, \"%s\"", OTELC_STR_ARG(str), bounds, bounds_num, OTELC_DPTR_ARGS(err), OTELC_STR_ARG(err_msg));

	buffer  = OTELC_STRDUP(str);
	*bounds = OTELC_CALLOC(bounds_size, sizeof(**bounds));
	if ((buffer == NULL) || (*bounds == NULL)) {
		OTELC_SFREE(buffer);
		OTELC_SFREE(*bounds);

		FLT_OTEL_PARSE_ERR(err, "'%s' : out of memory", err_msg);

		OTELC_RETURN_INT(retval);
	}

	/* Tokenize and parse space-separated boundary values. */
	for (token = strtok_r(buffer, " \t", &lasts); token != NULL; token = strtok_r(NULL, " \t", &lasts)) {
		if (!flt_otel_strtod(token, &value, 0.0, DBL_MAX, err)) {
			retval |= ERR_ABORT | ERR_ALERT;

			break;
		}
		else if (bounds_len >= bounds_size) {
			ptr = OTELC_REALLOC(*bounds, (bounds_size + 8) * sizeof(*ptr));
			if (ptr == NULL) {
				FLT_OTEL_PARSE_ERR(err, "'%s' : out of memory", err_msg);

				OTELC_SFREE_CLEAR(*bounds);

				break;
			}

			*bounds      = ptr;
			bounds_size += 8;
		}

		(*bounds)[bounds_len++] = value;
	}

	/* Sort the bounds and reject duplicates. */
	if ((*bounds != NULL) && (bounds_len > 1)) {
		size_t i;

		qsort(*bounds, bounds_len, sizeof(**bounds), flt_otel_qsort_compar_double);

		for (i = 1; i < bounds_len; i++)
			if (flt_otel_qsort_compar_double(*bounds + i - 1, *bounds + i) == 0) {
				FLT_OTEL_PARSE_ERR(err, "'%s' : duplicate boundary value '%.2f'", err_msg, (*bounds)[i]);

				OTELC_SFREE_CLEAR(*bounds);

				break;
			}
	}

	OTELC_SFREE(buffer);

	if (*bounds == NULL) {
		*bounds_num = 0;
	}
	else if (bounds_len == 0) {
		FLT_OTEL_PARSE_ERR(err, "'%s' : empty bounds", err_msg);

		OTELC_SFREE_CLEAR(*bounds);
		*bounds_num = 0;
	}
	else {
		*bounds_num = bounds_len;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_instrument - instrument keyword parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_instrument(const char *file, int line, char **args, const struct flt_otel_parse_data *pdata, char **err)
 *
 * ARGUMENTS
 *   file  - configuration file path
 *   line  - configuration file line number
 *   args  - configuration line arguments array
 *   pdata - keyword metadata (name, usage, argument limits)
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the "instrument" keyword inside an otel-scope section.  Two forms
 *   are supported: the "update" form that references an existing instrument by
 *   name and adds attributes to it, and the "create" form that defines a new
 *   metric instrument with a type, name, optional aggregation type (preceded by
 *   the 'aggr' keyword), optional description, optional unit, a single sample
 *   expression for the value, and optional histogram bucket boundaries
 *   (preceded by the 'bounds' keyword).  The 'bounds' keyword is only valid for
 *   histogram instrument types.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_instrument(const char *file, int line, char **args, const struct flt_otel_parse_data *pdata, char **err)
{
#define FLT_OTEL_PARSE_SCOPE_INSTRUMENT_DEF(a,b)   { OTELC_METRIC_INSTRUMENT_##a, b },
	static const struct {
		otelc_metric_instrument_t  type;
		const char                *keyword;
	} instr_type[] = { FLT_OTEL_PARSE_SCOPE_INSTRUMENT_DEFINES };
#undef FLT_OTEL_PARSE_SCOPE_INSTRUMENT_DEF
	struct flt_otel_conf_instrument *instr;
	int                              i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p:%p", OTELC_STR_ARG(file), line, args, pdata, OTELC_DPTR_ARGS(err));

	/* Look up the instrument type from args[1]. */
	for (i = 0; i < OTELC_TABLESIZE(instr_type); i++)
		if (FLT_OTEL_PARSE_KEYWORD(1, instr_type[i].keyword)) {
			OTELC_DBG(DEBUG, "instrument type: %d '%s'", instr_type[i].type, instr_type[i].keyword);

			break;
		}

	if (i >= OTELC_TABLESIZE(instr_type)) {
		FLT_OTEL_PARSE_ERR(err, "'%s' : invalid instrument type", args[1]);

		OTELC_RETURN_INT(retval);
	}

	/*
	 * Only one create and one update instrument per name are allowed.
	 * Pass NULL as head for update instruments to bypass the generic
	 * duplicate check (which would reject the shared name), check for
	 * update duplicates separately, and append to the list manually.
	 */
	if (instr_type[i].type == OTELC_METRIC_INSTRUMENT_UPDATE) {
		list_for_each_entry(instr, &(flt_otel_current_scope->instruments), list)
			if ((instr->type == OTELC_METRIC_INSTRUMENT_UPDATE) && FLT_OTEL_PARSE_KEYWORD(2, instr->id)) {
				FLT_OTEL_ERR("'%s' : already defined", args[2]);

				OTELC_RETURN_INT(retval);
			}

		instr = flt_otel_conf_instrument_init(args[2], line, NULL, err);
		if (instr != NULL)
			LIST_APPEND(&(flt_otel_current_scope->instruments), &(instr->list));
	} else {
		instr = flt_otel_conf_instrument_init(args[2], line, &(flt_otel_current_scope->instruments), err);
	}

	if (instr == NULL) {
		retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (instr_type[i].type == OTELC_METRIC_INSTRUMENT_UPDATE) {
		bool flag_add_attr = false;

		instr->type = instr_type[i].type;

		/* Update instruments only accept additional attributes. */
		for (i = 3; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++) {
			if (flag_add_attr) {
				if (!FLT_OTEL_ARG_ISVALID(i) || !FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else {
					retval = flt_otel_parse_cfg_sample(file, line, args, i + 1, 1, NULL, &(instr->attributes), err);
					if (!(retval & ERR_CODE))
						i++;
				}
			}
			else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_ATTR)) {
				flag_add_attr = true;
			}
			else {
				FLT_OTEL_PARSE_ERR(err, "'%s' : unknown keyword (use '%s%s')", args[i], pdata->name, pdata->usage);
			}
		}

		if (flag_add_attr && LIST_ISEMPTY(&(instr->attributes)))
			FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
	}
	else {
		instr->type = instr_type[i].type;

		/*
		 * Create instruments accept aggr, description, unit, value,
		 * and bounds.
		 */
		for (i = 3; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++) {
			if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_AGGR)) {
				if (!FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else if (instr->aggr_type != OTELC_METRIC_AGGREGATION_UNSET)
					FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
				else {
					otelc_metric_aggregation_type_t type = otelc_meter_aggr_parse(args[++i]);

					if (type == OTELC_RET_ERROR)
						FLT_OTEL_PARSE_ERR(err, "'%s' : invalid aggregation type", args[i]);
					else
						instr->aggr_type = type;
				}
			}
			else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_DESC)) {
				if (!FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else if (instr->description == NULL)
					retval = flt_otel_parse_strdup(&(instr->description), NULL, args[++i], err, args[0]);
				else
					FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
			}
			else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_UNIT)) {
				if (!FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else if (instr->unit == NULL)
					retval = flt_otel_parse_strdup(&(instr->unit), NULL, args[++i], err, args[0]);
				else
					FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
			}
			else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_VALUE)) {
				if (!FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else if (!LIST_ISEMPTY(&(instr->samples)))
					FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
				else {
					retval = flt_otel_parse_cfg_sample(file, line, args, ++i, 1, NULL, &(instr->samples), err);

					if (!(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i + 1) && !FLT_OTEL_PARSE_KEYWORD(i + 1, FLT_OTEL_PARSE_INSTRUMENT_AGGR) && !FLT_OTEL_PARSE_KEYWORD(i + 1, FLT_OTEL_PARSE_INSTRUMENT_DESC) && !FLT_OTEL_PARSE_KEYWORD(i + 1, FLT_OTEL_PARSE_INSTRUMENT_UNIT) && !FLT_OTEL_PARSE_KEYWORD(i + 1, FLT_OTEL_PARSE_INSTRUMENT_VALUE) && !FLT_OTEL_PARSE_KEYWORD(i + 1, FLT_OTEL_PARSE_INSTRUMENT_BOUNDS))
						FLT_OTEL_PARSE_ERR(err, "'%s' : only one sample expression allowed per instrument", args[0]);
				}
			}
			else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_INSTRUMENT_BOUNDS)) {
				if (!FLT_OTEL_ARG_ISVALID(i + 1))
					FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				else if (instr->type != OTELC_METRIC_INSTRUMENT_HISTOGRAM_UINT64)
					FLT_OTEL_PARSE_ERR(err, "'%s' : bounds only valid for hist_int instruments", args[i]);
				else if (instr->bounds != NULL)
					FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
				else
					retval = flt_otel_parse_bounds(args[++i], &(instr->bounds), &(instr->bounds_num), err, args[0]);
			}
			else {
				FLT_OTEL_PARSE_ERR(err, "'%s' : invalid argument (use '%s%s')", args[i], pdata->name, pdata->usage);
			}
		}
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_log_record - log-record keyword parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_log_record(const char *file, int line, char **args, const struct flt_otel_parse_data *pdata, char **err)
 *
 * ARGUMENTS
 *   file  - configuration file path
 *   line  - configuration file line number
 *   args  - configuration line arguments array
 *   pdata - keyword metadata (name, usage, argument limits)
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the "log-record" keyword inside an otel-scope section.  The first
 *   argument is a required severity level string.  Optional keywords "id",
 *   "event", "span", and "attr" follow in any order.  The remaining arguments
 *   at the end are parsed as fetch expressions or a log-format string.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_log_record(const char *file, int line, char **args, const struct flt_otel_parse_data *pdata, char **err)
{
	struct flt_otel_conf_log_record *log;
	otelc_log_severity_t             severity;
	int                              i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, %p, %p:%p", OTELC_STR_ARG(file), line, args, pdata, OTELC_DPTR_ARGS(err));

	/* Look up the severity level from args[1]. */
	severity = otelc_logger_severity_parse(args[1]);
	if (severity == OTELC_LOG_SEVERITY_INVALID) {
		FLT_OTEL_PARSE_ERR(err, "'%s' : invalid log severity", args[1]);

		OTELC_RETURN_INT(retval);
	}

	log = flt_otel_conf_log_record_init(FLT_OTEL_CONF_HDR_SPECIAL "log-record", line, &(flt_otel_current_scope->log_records), err);
	if (log == NULL) {
		retval |= ERR_ABORT | ERR_ALERT;

		OTELC_RETURN_INT(retval);
	}

	log->severity = severity;

	/* Parse optional keywords starting from args[2]. */
	for (i = 2; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++) {
		if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_LOG_RECORD_ID)) {
			if (!FLT_OTEL_ARG_ISVALID(i + 1))
				FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
			else if (log->event_id != 0)
				FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
			else if (!flt_otel_strtoll(args[++i], &(log->event_id), 0, LLONG_MAX, err))
				retval |= ERR_ABORT | ERR_ALERT;
		}
		else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_LOG_RECORD_EVENT)) {
			if (!FLT_OTEL_ARG_ISVALID(i + 1))
				FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
			else if (log->event_name != NULL)
				FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
			else
				retval = flt_otel_parse_strdup(&(log->event_name), NULL, args[++i], err, args[0]);
		}
		else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_LOG_RECORD_SPAN)) {
			if (!FLT_OTEL_ARG_ISVALID(i + 1))
				FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
			else if (log->span != NULL)
				FLT_OTEL_PARSE_ERR(err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
			else
				retval = flt_otel_parse_strdup(&(log->span), NULL, args[++i], err, args[0]);
		}
		else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_LOG_RECORD_ATTR)) {
			if (!FLT_OTEL_ARG_ISVALID(i + 1) || !FLT_OTEL_ARG_ISVALID(i + 2))
				FLT_OTEL_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
			else {
				retval = flt_otel_parse_cfg_sample(file, line, args, i + 2, 1, NULL, &(log->attributes), err);
				if (!(retval & ERR_CODE))
					i += 2;
			}
		}
		else {
			/*
			 * Not a recognized keyword -- the remaining arguments
			 * are sample fetch expressions or a log-format string.
			 */
			retval = flt_otel_parse_cfg_sample(file, line, args, i, 0, NULL, &(log->samples), err);

			break;
		}
	}

	if (!(retval & ERR_CODE) && LIST_ISEMPTY(&(log->samples)))
		FLT_OTEL_PARSE_ERR(err, "'%s' : missing body expression (use '%s%s')", args[0], pdata->name, pdata->usage);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg_scope - otel-scope section parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg_scope(const char *file, int line, char **args, int kw_mod)
 *
 * ARGUMENTS
 *   file   - configuration file path
 *   line   - configuration file line number
 *   args   - configuration line arguments array
 *   kw_mod - keyword modifier flags (e.g. KWM_NO)
 *
 * DESCRIPTION
 *   Section parser for the otel-scope configuration block.  Handles keywords:
 *   scope ID, span (with optional root/parent/link modifiers), link, attribute,
 *   event, baggage, status, inject, extract, finish, instrument, log-record,
 *   acl, and otel-event (with optional if/unless conditions).
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg_scope(const char *file, int line, char **args, int kw_mod)
{
#define FLT_OTEL_PARSE_SCOPE_DEF(a,b,c,d,e,f,g)   { FLT_OTEL_PARSE_SCOPE_##a, b, FLT_OTEL_PARSE_INVALID_##c, d, e, f, g },
	static const struct flt_otel_parse_data  parse_data[] = { FLT_OTEL_PARSE_SCOPE_DEFINES };
#undef FLT_OTEL_PARSE_SCOPE_DEF
	const struct flt_otel_parse_data        *pdata = NULL;
	char                                    *err = NULL;
	int                                      i, retval = ERR_NONE;

	OTELC_FUNC("\"%s\", %d, %p, 0x%08x", OTELC_STR_ARG(file), line, args, kw_mod);

	if (flt_otel_parse_check_scope())
		OTELC_RETURN_INT(retval);

	/* Validate and identify the scope keyword. */
	retval = flt_otel_parse_cfg_check(file, line, args, flt_otel_current_span, parse_data, OTELC_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OTEL_PARSE_IFERR_ALERT();

		OTELC_RETURN_INT(retval);
	}

	/* Handle keyword-specific scope configuration. */
	if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_ID) {
		/* Initialization of a new scope. */
		flt_otel_current_scope = flt_otel_conf_scope_init(args[1], line, &(flt_otel_current_config->scopes), &err);
		if (flt_otel_current_scope == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_SPAN) {
		/*
		 * Checking if this is the beginning of the definition of
		 * a new span.
		 */
		if (flt_otel_current_span != NULL) {
			OTELC_DBG(DEBUG, "span '%s' (done)", flt_otel_current_span->id);

			flt_otel_current_span = NULL;
		}

		/* Initialization of a new span. */
		flt_otel_current_span = flt_otel_conf_span_init(args[1], line, &(flt_otel_current_scope->spans), &err);

		/*
		 * In case the span has a defined reference (parent), the
		 * correctness of the arguments is checked here.
		 */
		if (flt_otel_current_span == NULL) {
			retval |= ERR_ABORT | ERR_ALERT;
		}
		else if (FLT_OTEL_ARG_ISVALID(2)) {
			for (i = 2; (i < pdata->args_max) && FLT_OTEL_ARG_ISVALID(i); i++) {
				if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_SPAN_ROOT)) {
					if (flt_otel_current_span->flag_root)
						FLT_OTEL_PARSE_ERR(&err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
					else
						flt_otel_current_span->flag_root = 1;
				}
				else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_SPAN_PARENT)) {
					if (FLT_OTEL_ARG_ISVALID(i + 1))
						retval |= flt_otel_parse_strdup(&(flt_otel_current_span->ref_id), &(flt_otel_current_span->ref_id_len), args[++i], &err, args[1]);
					else
						FLT_OTEL_PARSE_ERR(&err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
				}
				else if (FLT_OTEL_PARSE_KEYWORD(i, FLT_OTEL_PARSE_SPAN_LINK)) {
					if (FLT_OTEL_ARG_ISVALID(i + 1)) {
						if (flt_otel_conf_link_init(args[++i], line, &(flt_otel_current_span->links), &err) == NULL)
							retval |= ERR_ABORT | ERR_ALERT;
					} else {
						FLT_OTEL_PARSE_ERR(&err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
					}
				}
				else {
					FLT_OTEL_PARSE_ERR(&err, "'%s' : invalid argument (use '%s%s')", args[i], pdata->name, pdata->usage);
				}
			}
		}
		else {
			/*
			 * This is not a faulty configuration, only such a case
			 * will be logged.
			 */
			OTELC_DBG(DEBUG, "new span '%s' without reference", flt_otel_current_span->id);
		}
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_LINK) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(i); i++)
			if (flt_otel_conf_link_init(args[i], line, &(flt_otel_current_span->links), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_ATTRIBUTE) {
		retval = flt_otel_parse_cfg_sample(file, line, args, 2, 0, NULL, &(flt_otel_current_span->attributes), &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_EVENT) {
		struct otelc_value extra = { .u_type = OTELC_VALUE_STRING, .u.value_string = args[1] };

		retval = flt_otel_parse_cfg_sample(file, line, args, 3, 0, &extra, &(flt_otel_current_span->events), &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_BAGGAGE) {
		retval = flt_otel_parse_cfg_sample(file, line, args, 2, 0, NULL, &(flt_otel_current_span->baggages), &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_STATUS) {
#define FLT_OTEL_PARSE_SCOPE_STATUS_DEF(a,b)   { OTELC_SPAN_STATUS_##a, b },
		static const struct {
			int         code;
			const char *keyword;
		} status[] = { FLT_OTEL_PARSE_SCOPE_STATUS_DEFINES };
#undef FLT_OTEL_PARSE_SCOPE_STATUS_DEF

		for (i = 0; i < OTELC_TABLESIZE(status); i++)
			if (FLT_OTEL_PARSE_KEYWORD(1, status[i].keyword)) {
				OTELC_DBG(DEBUG, "span status: %d '%s'", status[i].code, status[i].keyword);

				break;
			}

		/*
		 * Regardless of the use of the list, only one status per event
		 * is allowed.
		 */
		if (i >= OTELC_TABLESIZE(status)) {
			FLT_OTEL_PARSE_ERR(&err, "'%s' : invalid span status", args[1]);
		}
		else if (LIST_ISEMPTY(&(flt_otel_current_span->statuses))) {
			struct otelc_value extra = { .u_type = OTELC_VALUE_INT32, .u.value_int32 = status[i].code };

			retval = flt_otel_parse_cfg_sample(file, line, args, 2, 0, &extra, &(flt_otel_current_span->statuses), &err);
		}
		else {
			FLT_OTEL_PARSE_ERR(&err, "only one status per event is allowed");
		}
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_INJECT) {
		/*
		 * Automatic context name generation can be specified here if
		 * the contents of the FLT_OTEL_PARSE_CTX_AUTONAME macro are
		 * used as the name.  In that case, if the context is after a
		 * particular event, it gets its name; otherwise it gets the
		 * name of the current span.
		 */
		if (flt_otel_current_span->ctx_id != NULL)
			FLT_OTEL_PARSE_ERR(&err, "'%s' : only one context per span is allowed", args[1]);
		else if (!FLT_OTEL_PARSE_KEYWORD(1, FLT_OTEL_PARSE_CTX_AUTONAME))
			retval = flt_otel_parse_strdup(&(flt_otel_current_span->ctx_id), &(flt_otel_current_span->ctx_id_len), args[1], &err, args[0]);
		else if (flt_otel_current_scope->event != FLT_OTEL_EVENT__NONE)
			retval = flt_otel_parse_strdup(&(flt_otel_current_span->ctx_id), &(flt_otel_current_span->ctx_id_len), flt_otel_event_data[flt_otel_current_scope->event].name, &err, args[0]);
		else {
			const char *ch;

			ch = invalid_prefix_char(flt_otel_current_span->id);
			if (ch == NULL)
				retval = flt_otel_parse_strdup(&(flt_otel_current_span->ctx_id), &(flt_otel_current_span->ctx_id_len), flt_otel_current_span->id, &err, args[0]);
			else
				FLT_OTEL_PARSE_ERR(&err, "'%s' : character '%c' is not permitted in the context name", flt_otel_current_span->id, *ch);
		}

		if (flt_otel_current_span->ctx_id != NULL) {
			/*
			 * Here is checked the context storage type; which, if
			 * not explicitly specified, is set to HTTP headers.
			 *
			 * It is possible to use both types of context storage
			 * at the same time.
			 */
			if (FLT_OTEL_ARG_ISVALID(2)) {
				retval |= flt_otel_parse_cfg_scope_ctx(args, 2, &err);
				if (!(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(3))
					retval |= flt_otel_parse_cfg_scope_ctx(args, 3, &err);
			} else {
				flt_otel_current_span->ctx_flags = FLT_OTEL_CTX_USE_HEADERS;
			}
		}
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_EXTRACT) {
		struct flt_otel_conf_context *conf_ctx;

		/*
		 * Here is checked the context storage type; which, if
		 * not explicitly specified, is set to HTTP headers.
		 */
		conf_ctx = flt_otel_conf_context_init(args[1], line, &(flt_otel_current_scope->contexts), &err);
		if (conf_ctx == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
		else if (!FLT_OTEL_ARG_ISVALID(2))
			conf_ctx->flags = FLT_OTEL_CTX_USE_HEADERS;
		else if (FLT_OTEL_PARSE_KEYWORD(2, FLT_OTEL_PARSE_CTX_USE_HEADERS))
			conf_ctx->flags = FLT_OTEL_CTX_USE_HEADERS;
#ifdef USE_OTEL_VARS
		else if (FLT_OTEL_PARSE_KEYWORD(2, FLT_OTEL_PARSE_CTX_USE_VARS))
			conf_ctx->flags = FLT_OTEL_CTX_USE_VARS;
#endif
		else
			FLT_OTEL_PARSE_ERR(&err, "'%s' : invalid context storage type", args[2]);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_FINISH) {
		retval = flt_otel_parse_cfg_str(file, line, args, &(flt_otel_current_scope->spans_to_finish), &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_INSTRUMENT) {
		retval = flt_otel_parse_cfg_instrument(file, line, args, pdata, &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_LOG_RECORD) {
		retval = flt_otel_parse_cfg_log_record(file, line, args, pdata, &err);
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_ACL) {
		if (FLT_OTEL_PARSE_KEYWORD(1, "or"))
			FLT_OTEL_PARSE_ERR(&err, "'%s %s ...' : invalid ACL name", args[0], args[1]);
		else if (parse_acl((const char **)args + 1, &(flt_otel_current_scope->acls), &err, &(flt_otel_current_config->proxy->conf.args), file, line) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_IDLE_TIMEOUT) {
		const char *res;
		uint        timeout;

		res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER)
			FLT_OTEL_PARSE_ERR(&err, "'%s' : timer overflow in argument '%s'", args[0], args[1]);
		else if (res == PARSE_TIME_UNDER)
			FLT_OTEL_PARSE_ERR(&err, "'%s' : timer underflow in argument '%s'", args[0], args[1]);
		else if (res != NULL)
			FLT_OTEL_PARSE_ERR(&err, "'%s' : unexpected character '%c' in '%s'", args[0], *res, args[1]);
		else if (timeout == 0)
			FLT_OTEL_PARSE_ERR(&err, "'%s' : value must be greater than zero", args[0]);
		else
			flt_otel_current_scope->idle_timeout = timeout;
	}
	else if (pdata->keyword == FLT_OTEL_PARSE_SCOPE_ON_EVENT) {
		/* Scope can only have one event defined. */
		if (flt_otel_current_scope->event != FLT_OTEL_EVENT__NONE) {
			FLT_OTEL_PARSE_ERR(&err, "'%s' : event already set", flt_otel_current_scope->id);
		} else {
			/* Check the event name. */
			for (i = 0; i < OTELC_TABLESIZE(flt_otel_event_data); i++)
				if (FLT_OTEL_PARSE_KEYWORD(1, flt_otel_event_data[i].name)) {
					flt_otel_current_scope->event = i;

					break;
				}

			/*
			 * The event can have some condition defined and this
			 * is checked here.
			 */
			if (flt_otel_current_scope->event == FLT_OTEL_EVENT__NONE) {
				FLT_OTEL_PARSE_ERR(&err, "'%s' : unknown event", args[1]);
			}
			else if (!FLT_OTEL_ARG_ISVALID(2)) {
				/* Do nothing. */
			}
			else if (FLT_OTEL_PARSE_KEYWORD(2, FLT_OTEL_CONDITION_IF) || FLT_OTEL_PARSE_KEYWORD(2, FLT_OTEL_CONDITION_UNLESS)) {
				/*
				 * We will first try to build ACL condition using
				 * local settings and then if that fails, using
				 * global settings (from instrumentation block).
				 * If it also fails, then try to use ACL defined
				 * in the HAProxy configuration.
				 */
				if (flt_otel_current_config->instr == NULL) {
					FLT_OTEL_PARSE_ERR(&err, "'%s' : instrumentation not defined", args[1]);
				} else {
					flt_otel_current_scope->cond = flt_otel_parse_acl(file, line, flt_otel_current_config->proxy, (const char **)args + 2, &err, &(flt_otel_current_scope->acls), &(flt_otel_current_config->instr->acls), &(flt_otel_current_config->proxy->acl), NULL);
					if (flt_otel_current_scope->cond == NULL)
						retval |= ERR_ABORT | ERR_ALERT;
				}
			}
			else {
				FLT_OTEL_PARSE_ERR(&err, "'%s' : expects either 'if' or 'unless' followed by a condition but found '%s'", args[1], args[2]);
			}

			if (!(retval & ERR_CODE))
				OTELC_DBG(DEBUG, "event '%s'", args[1]);
		}
	}

	FLT_OTEL_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_otel_current_scope != NULL)) {
		flt_otel_conf_scope_free(&flt_otel_current_scope);

		flt_otel_current_span = NULL;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_post_parse_cfg_scope - otel-scope post-parse check
 *
 * SYNOPSIS
 *   static int flt_otel_post_parse_cfg_scope(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Post-parse callback for the otel-scope section.  Verifies that HTTP header
 *   injection is only used on events that support it.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_post_parse_cfg_scope(void)
{
	struct flt_otel_conf_span *conf_span;
	int                      retval = ERR_NONE;

	OTELC_FUNC("");

	if (flt_otel_current_scope == NULL)
		OTELC_RETURN_INT(retval);

	/* If span context inject is used, check that this is possible. */
	list_for_each_entry(conf_span, &(flt_otel_current_scope->spans), list)
		if ((conf_span->ctx_id != NULL) && (conf_span->ctx_flags & FLT_OTEL_CTX_USE_HEADERS))
			if (!flt_otel_event_data[flt_otel_current_scope->event].flag_http_inject)
				FLT_OTEL_POST_PARSE_ALERT("inject '%s' : cannot use on this event", conf_span->cfg_line, conf_span->ctx_id);

	/* Validate idle-timeout / on-idle-timeout consistency. */
	if (flt_otel_current_scope->idle_timeout == 0) {
		if (flt_otel_current_scope->event == FLT_OTEL_EVENT__IDLE_TIMEOUT)
			FLT_OTEL_POST_PARSE_ALERT("'%s' : 'idle-timeout' is required for event 'on-idle-timeout'", flt_otel_current_scope->cfg_line, flt_otel_current_scope->id);
	}
	else if (flt_otel_current_scope->event != FLT_OTEL_EVENT__IDLE_TIMEOUT) {
		FLT_OTEL_POST_PARSE_ALERT("'%s' : 'idle-timeout' can only be used with event 'on-idle-timeout'", flt_otel_current_scope->cfg_line, flt_otel_current_scope->id);
	}

	if (retval & ERR_CODE)
		flt_otel_conf_scope_free(&flt_otel_current_scope);

	flt_otel_current_scope = NULL;
	flt_otel_current_span  = NULL;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse_cfg - OTel configuration file parser
 *
 * SYNOPSIS
 *   static int flt_otel_parse_cfg(struct flt_otel_conf *conf, const char *flt_name, char **err)
 *
 * ARGUMENTS
 *   conf     - pointer to the filter configuration structure
 *   flt_name - filter name for error reporting
 *   err      - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the OTel filter configuration file.  Backs up the current HAProxy
 *   section parsers, registers temporary otel-instrumentation, otel-group, and
 *   otel-scope section parsers, loads and parses the file, then restores the
 *   original sections.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse_cfg(struct flt_otel_conf *conf, const char *flt_name, char **err)
{
	struct list    backup_sections;
	struct cfgfile cfg_file;
	int            retval = ERR_ABORT | ERR_ALERT;

	OTELC_FUNC("%p, \"%s\", %p:%p", conf, OTELC_STR_ARG(flt_name), OTELC_DPTR_ARGS(err));

	flt_otel_current_config = conf;

	/* Backup sections. */
	LIST_INIT(&backup_sections);
	cfg_backup_sections(&backup_sections);

	/* Register new OTEL sections and parse the OTEL filter configuration file. */
	if (!cfg_register_section(FLT_OTEL_PARSE_SECTION_INSTR_ID, flt_otel_parse_cfg_instr, flt_otel_post_parse_cfg_instr))
		/* Do nothing. */;
	else if (!cfg_register_section(FLT_OTEL_PARSE_SECTION_GROUP_ID, flt_otel_parse_cfg_group, flt_otel_post_parse_cfg_group))
		/* Do nothing. */;
	else if (!cfg_register_section(FLT_OTEL_PARSE_SECTION_SCOPE_ID, flt_otel_parse_cfg_scope, flt_otel_post_parse_cfg_scope))
		/* Do nothing. */;
	else if (access(conf->cfg_file, R_OK) == -1)
		FLT_OTEL_PARSE_ERR(err, "'%s' : %s", conf->cfg_file, strerror(errno));
	else {
		struct list saved_args = LIST_HEAD_INIT(saved_args);

		/*
		 * Sample fetch arguments queued during parsing are normally
		 * resolved by smp_resolve_args() in the proxy
		 * post-configuration phase.  That call uses the proxy's own
		 * capabilities, so backend-only fetches like be_conn would
		 * fail when the filter is attached to a frontend.
		 *
		 * The OTel filter spans both request and response channels,
		 * so its sample fetches must be resolved with full FE+BE
		 * capabilities.  To achieve this the proxy's arg list is saved
		 * and replaced with a fresh one before parsing.  The OTel
		 * config parser adds only ARGC_OTEL entries to the new list.
		 * After parsing, those entries are moved to conf->smp_args and
		 * resolved later in flt_otel_check(), which runs after all
		 * configuration sections have been parsed so that backends and
		 * servers are available.
		 */
		LIST_SPLICE(&saved_args, &(conf->proxy->conf.args.list));
		LIST_INIT(&(conf->proxy->conf.args.list));

		(void)memset(&cfg_file, 0, sizeof(cfg_file));
		cfg_file.filename = conf->cfg_file;
		cfg_file.size     = load_cfg_in_mem(cfg_file.filename, &(cfg_file.content));
		if (cfg_file.size >= 0)
			retval = parse_cfg(&cfg_file);
		ha_free(&(cfg_file.content));

		/* Stash OTEL args for deferred resolution. */
		LIST_SPLICE(&(conf->smp_args), &(conf->proxy->conf.args.list));
		LIST_INIT(&(conf->proxy->conf.args.list));

		/* Restore the original arg list unchanged. */
		LIST_SPLICE(&(conf->proxy->conf.args.list), &saved_args);
	}

	/* Unregister OTEL sections and restore previous sections. */
	cfg_unregister_sections();
	cfg_restore_sections(&backup_sections);

	flt_otel_current_config = NULL;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_parse - main filter parser entry point
 *
 * SYNOPSIS
 *   static int flt_otel_parse(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf, char **err, void *private)
 *
 * ARGUMENTS
 *   args    - configuration line arguments array
 *   cur_arg - pointer to the current argument index
 *   px      - proxy instance owning the filter
 *   fconf   - filter configuration structure to populate
 *   err     - indirect pointer to error message string
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Main filter parser entry point, registered for the "otel" filter keyword.
 *   Parses the filter ID and configuration file path from the HAProxy
 *   configuration line.  If no filter ID is specified, the default ID is used.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf, char **err, void *private)
{
	struct flt_otel_conf *conf = NULL;
	int                   pos, retval = ERR_NONE;

	OTELC_FUNC("%p, %p, %p, %p, %p:%p, %p", args, cur_arg, px, fconf, OTELC_DPTR_ARGS(err), private);

	OTELC_DBG_IFDEF(otelc_dbg_level = FLT_OTEL_DEBUG_LEVEL, );

#ifdef OTELC_DBG_MEM
	/* Initialize the debug memory tracker before the first allocation. */
	FLT_OTEL_RUN_ONCE(
		if (otelc_dbg_mem_init(&dbg_mem, dbg_mem_data, OTELC_TABLESIZE(dbg_mem_data)) == -1) {
			FLT_OTEL_PARSE_ERR(err, "cannot initialize memory debugger");

			OTELC_RETURN_INT(retval);
		}
	);
#endif

	FLT_OTEL_ARGS_DUMP();

	conf = flt_otel_conf_init(px);
	if (conf == NULL) {
		FLT_OTEL_PARSE_ERR(err, "'%s' : out of memory", args[*cur_arg]);

		OTELC_RETURN_INT(retval);
	}

	/* Process filter option key-value pairs. */
	for (pos = *cur_arg + 1; !(retval & ERR_CODE) && FLT_OTEL_ARG_ISVALID(pos); pos++) {
		OTELC_DBG(DEBUG, "args[%d:2]: { '%s' '%s' }", pos, args[pos], args[pos + 1]);

		if (FLT_OTEL_PARSE_KEYWORD(pos, FLT_OTEL_OPT_FILTER_ID)) {
			retval = flt_otel_parse_keyword(&(conf->id), args, *cur_arg, pos, err, "name");
			pos++;
		}
		else if (FLT_OTEL_PARSE_KEYWORD(pos, FLT_OTEL_OPT_CONFIG)) {
			retval = flt_otel_parse_keyword(&(conf->cfg_file), args, *cur_arg, pos, err, "configuration file");
			if (!(retval & ERR_CODE))
				retval = flt_otel_parse_cfg(conf, args[*cur_arg], err);
			pos++;
		}
		else {
			FLT_OTEL_PARSE_ERR(err, "'%s' : unknown keyword '%s'", args[*cur_arg], args[pos]);
		}
	}

	/* If the OpenTelemetry filter ID is not set, use default name. */
	if (!(retval & ERR_CODE) && (conf->id == NULL)) {
		ha_warning("parsing : " FLT_OTEL_FMT_TYPE FLT_OTEL_FMT_NAME "'no filter id set, using default id '%s'\n", FLT_OTEL_OPT_FILTER_ID_DEFAULT);

		retval = flt_otel_parse_strdup(&(conf->id), NULL, FLT_OTEL_OPT_FILTER_ID_DEFAULT, err, args[*cur_arg]);
	}

	if (!(retval & ERR_CODE) && (conf->cfg_file == NULL))
		FLT_OTEL_PARSE_ERR(err, "'%s' : no configuration file specified", args[*cur_arg]);

	if (retval & ERR_CODE) {
		flt_otel_conf_free(&conf);
	} else {
		fconf->id   = otel_flt_id;
		fconf->ops  = &flt_otel_ops;
		fconf->conf = conf;

		*cur_arg = pos;

		OTELC_DBG(DEBUG, "filter set: id '%s', config '%s'", conf->id, conf->cfg_file);
		FLT_OTEL_DBG_CONF("- conf ", (typeof(conf))fconf->conf);
	}

	OTELC_RETURN_INT(retval);
}


/* Declare the filter parser for FLT_OTEL_OPT_NAME keyword. */
static struct flt_kw_list flt_kws = { FLT_OTEL_SCOPE, { }, {
		{ FLT_OTEL_OPT_NAME, flt_otel_parse, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
