/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "include.h"


#ifdef DEBUG_OT
struct flt_ot_debug               flt_ot_debug;
THREAD_LOCAL int                  dbg_indent_level = 0;
#endif

#ifdef OTC_DBG_MEM
static struct otc_dbg_mem_data    dbg_mem_data[1000000];
static struct otc_dbg_mem         dbg_mem;
#endif

static struct flt_ot_conf        *flt_ot_current_config = NULL;
static struct flt_ot_conf_tracer *flt_ot_current_tracer = NULL;
static struct flt_ot_conf_group  *flt_ot_current_group = NULL;
static struct flt_ot_conf_scope  *flt_ot_current_scope = NULL;
static struct flt_ot_conf_span   *flt_ot_current_span = NULL;


/***
 * NAME
 *   flt_ot_parse_strdup -
 *
 * ARGUMENTS
 *   ptr     -
 *   str     -
 *   err     -
 *   err_msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_strdup(char **ptr, const char *str, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	FLT_OT_FUNC("%p:%p, %p, %p:%p, \"%s\"", FLT_OT_DPTR_ARGS(ptr), str, FLT_OT_DPTR_ARGS(err), err_msg);

	*ptr = FLT_OT_STRDUP(str);
	if (*ptr == NULL) {
		FLT_OT_PARSE_ERR(err, "'%s' : out of memory", err_msg);

		retval |= ERR_ABORT | ERR_ALERT;
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_keyword -
 *
 * ARGUMENTS
 *   ptr     -
 *   args    -
 *   cur_arg -
 *   pos     -
 *   err     -
 *   err_msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_keyword(char **ptr, char **args, int cur_arg, int pos, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	FLT_OT_FUNC("%p:%p, %p, %d, %d, %p:%p, \"%s\"", FLT_OT_DPTR_ARGS(ptr), args, cur_arg, pos, FLT_OT_DPTR_ARGS(err), err_msg);

	if (*ptr != NULL) {
		if (cur_arg == pos)
			FLT_OT_PARSE_ERR(err, FLT_OT_FMT_TYPE "%s already set", err_msg);
		else
			FLT_OT_PARSE_ERR(err, "'%s' : %s already set", args[cur_arg], err_msg);
	}
	else if (!FLT_OT_ARG_ISVALID(pos + 1)) {
		if (cur_arg == pos)
			FLT_OT_PARSE_ERR(err, FLT_OT_FMT_TYPE "no %s set", err_msg);
		else
			FLT_OT_PARSE_ERR(err, "'%s' : no %s set", args[cur_arg], err_msg);
	}
	else {
		retval = flt_ot_parse_strdup(ptr, args[pos + 1], err, args[cur_arg]);
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_invalid_char -
 *
 * ARGUMENTS
 *   name -
 *   type -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static const char *flt_ot_parse_invalid_char(const char *name, int type)
{
	const char *retptr = NULL;

	FLT_OT_FUNC("\"%s\", %d", name, type);

	if (!FLT_OT_STR_ISVALID(name))
		FLT_OT_RETURN(retptr);

	if (type == 1) {
		retptr = invalid_char(name);
	}
	else if (type == 2) {
		retptr = invalid_domainchar(name);
	}
	else if (type == 3) {
		retptr = invalid_prefix_char(name);
	}
	else if (type == 4) {
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

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_parse_cfg_check -
 *
 * ARGUMENTS
 *   file            -
 *   linenum         -
 *   args            -
 *   id              -
 *   parse_data      -
 *   parse_data_size -
 *   pdata           -
 *   err             -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_check(const char *file, int linenum, char **args, const void *id, const struct flt_ot_parse_data *parse_data, size_t parse_data_size, const struct flt_ot_parse_data **pdata, char **err)
{
	int i, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, %p, %p, %zu, %p:%p, %p:%p", file, linenum, args, id, parse_data, parse_data_size, FLT_OT_DPTR_ARGS(pdata), FLT_OT_DPTR_ARGS(err));

	FLT_OT_ARGS_DUMP();

	*pdata = NULL;

	for (i = 0; (*pdata == NULL) && (i < parse_data_size); i++)
		if (strcmp(parse_data[i].name, args[0]) == 0)
			*pdata = parse_data + i;

	if (*pdata == NULL)
		FLT_OT_PARSE_ERR(err, "'%s' : unknown keyword", args[0]);

	if ((retval & ERR_CODE) || (id == NULL))
		/* Do nothing. */;
	else if ((id != flt_ot_current_tracer) && (flt_ot_current_config->tracer == NULL))
		FLT_OT_PARSE_ERR(err, "tracer not defined");

	/*
	 * Checking that fewer arguments are specified in the configuration
	 * line than is required.
	 */
	if (!(retval & ERR_CODE))
		for (i = 1; i < (*pdata)->args_min; i++)
			if (!FLT_OT_ARG_ISVALID(i))
				FLT_OT_PARSE_ERR(err, "'%s' : too few arguments (use '%s%s')", args[0], (*pdata)->name, (*pdata)->usage);

	/*
	 * Checking that more arguments are specified in the configuration
	 * line than the maximum allowed.
	 */
	if (!(retval & ERR_CODE) && ((*pdata)->args_max > 0)) {
		for ( ; (i <= (*pdata)->args_max) && FLT_OT_ARG_ISVALID(i); i++);

		if (i > (*pdata)->args_max)
			FLT_OT_PARSE_ERR(err, "'%s' : too many arguments (use '%s%s')", args[0], (*pdata)->name, (*pdata)->usage);
	}

	/* Checking that the first argument has only allowed characters. */
	if (!(retval & ERR_CODE) && ((*pdata)->check_name > 0)) {
		const char *ic;

		ic = flt_ot_parse_invalid_char(args[1], (*pdata)->check_name);
		if (ic != NULL)
			FLT_OT_PARSE_ERR(err, "%s '%s' : invalid character '%c'", args[0], args[1], *ic);
	}

	/* Checking that the data group name is defined. */
	if (!(retval & ERR_CODE) && (*pdata)->flag_check_id && (id == NULL))
		FLT_OT_PARSE_ERR(err, "'%s' : %s ID not set (use '%s%s')", args[0], parse_data[1].name, parse_data[1].name, parse_data[1].usage);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_sample_expr -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   idx     -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_sample_expr(const char *file, int linenum, char **args, int *idx, struct list *head, char **err)
{
	struct flt_ot_conf_sample_expr *expr;
	int                             retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, %p, %p, %p:%p", file, linenum, args, idx, head, FLT_OT_DPTR_ARGS(err));

	expr = flt_ot_conf_sample_expr_init(args[*idx], linenum, head, err);
	if (expr != NULL) {
		expr->expr = sample_parse_expr(args, idx, file, linenum, err, &(flt_ot_current_config->proxy->conf.args), NULL);
		if (expr->expr != NULL)
			FLT_OT_DBG(3, "sample expression '%s' added", expr->value);
		else
			retval |= ERR_ABORT | ERR_ALERT;
	} else {
			retval |= ERR_ABORT | ERR_ALERT;
	}

	if (retval & ERR_CODE)
		flt_ot_conf_sample_expr_free(&expr);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_sample -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_sample(const char *file, int linenum, char **args, struct list *head, char **err)
{
	struct flt_ot_conf_sample *sample;
	int                        idx = 2, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, %p, %p:%p", file, linenum, args, head, FLT_OT_DPTR_ARGS(err));

	sample = flt_ot_conf_sample_init(args, linenum, head, err);
	if (sample == NULL)
		FLT_OT_PARSE_ERR(err, "'%s' : out of memory", args[0]);

	if (!(retval & ERR_CODE)) {
		flt_ot_current_config->proxy->conf.args.ctx  = ARGC_OT;
		flt_ot_current_config->proxy->conf.args.file = file;
		flt_ot_current_config->proxy->conf.args.line = linenum;

		while (!(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(idx))
			retval = flt_ot_parse_cfg_sample_expr(file, linenum, args, &idx, &(sample->exprs), err);

		flt_ot_current_config->proxy->conf.args.file = NULL;
		flt_ot_current_config->proxy->conf.args.line = 0;
	}

	if (retval & ERR_CODE)
		flt_ot_conf_sample_free(&sample);
	else
		FLT_OT_DBG(3, "sample '%s' -> '%s' added", sample->key, sample->value);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_str -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_str(const char *file, int linenum, char **args, struct list *head, char **err)
{
	struct flt_ot_conf_str *str = NULL;
	int                     i, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, %p, %p:%p", file, linenum, args, head, FLT_OT_DPTR_ARGS(err));

	for (i = 1; !(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(i); i++)
		if (flt_ot_conf_str_init(args[i], linenum, head, err) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;

	if (retval & ERR_CODE)
		flt_ot_conf_str_free(&str);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_file -
 *
 * ARGUMENTS
 *   ptr     -
 *   file    -
 *   linenum -
 *   args    -
 *   err     -
 *   err_msg -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_file(char **ptr, const char *file, int linenum, char **args, char **err, const char *err_msg)
{
	int retval = ERR_NONE;

	FLT_OT_FUNC("%p:%p, \"%s\", %d, %p, %p:%p, \"%s\"", FLT_OT_DPTR_ARGS(ptr), file, linenum, args, FLT_OT_DPTR_ARGS(err), err_msg);

	if (!FLT_OT_ARG_ISVALID(1))
		FLT_OT_PARSE_ERR(err, "'%s' : no %s specified", flt_ot_current_tracer->id, err_msg);
	else if (alertif_too_many_args(1, file, linenum, args, &retval))
		retval |= ERR_ABORT | ERR_ALERT;
	else if (access(args[1], R_OK) == -1)
		FLT_OT_PARSE_ERR(err, "'%s' : %s", args[1], strerror(errno));
	else
		retval = flt_ot_parse_keyword(ptr, args, 0, 0, err, err_msg);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_check_scope -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns TRUE in case the configuration is not in the currently defined
 *   scope, FALSE otherwise.
 */
static bool flt_ot_parse_check_scope(void)
{
	bool retval = 0;

	if ((cfg_scope != NULL) && (flt_ot_current_config->id != NULL) && (strcmp(flt_ot_current_config->id, cfg_scope) != 0)) {
		FLT_OT_DBG(1, "cfg_scope: '%s', id: '%s'", cfg_scope, flt_ot_current_config->id);

		retval = 1;
	}

	return retval;
}


/***
 * NAME
 *   flt_ot_parse_cfg_tracer -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   kw_mod  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_tracer(const char *file, int linenum, char **args, int kw_mod)
{
#define FLT_OT_PARSE_TRACER_DEF(a,b,c,d,e,f,g)   { FLT_OT_PARSE_TRACER_##a, b, c, d, e, f, g },
	static const struct flt_ot_parse_data  parse_data[] = { FLT_OT_PARSE_TRACER_DEFINES };
#undef FLT_OT_PARSE_TRACER_DEF
	const struct flt_ot_parse_data        *pdata = NULL;
	char                                  *err = NULL, *err_log = NULL;
	int                                    i, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, 0x%08x", file, linenum, args, kw_mod);

	if (flt_ot_parse_check_scope())
		FLT_OT_RETURN(retval);

	retval = flt_ot_parse_cfg_check(file, linenum, args, flt_ot_current_tracer, parse_data, FLT_OT_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OT_PARSE_IFERR_ALERT();

		FLT_OT_RETURN(retval);
	}

	if (pdata->keyword == FLT_OT_PARSE_TRACER_ID) {
		if (flt_ot_current_config->tracer != NULL) {
			FLT_OT_PARSE_ERR(&err, "'%s' : tracer can be defined only once", args[1]);
		} else {
			flt_ot_current_tracer = flt_ot_conf_tracer_init(args[1], linenum, &err);
			if (flt_ot_current_tracer == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
		}
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_LOG) {
		if (parse_logsrv(args, &(flt_ot_current_tracer->proxy_log.logsrvs), kw_mod == KWM_NO, &err_log) == 0) {
			FLT_OT_PARSE_ERR(&err, "'%s %s ...' : %s", args[0], args[1], err_log);
			FLT_OT_FREE_CLEAR(err_log);

			retval |= ERR_ABORT | ERR_ALERT;
		} else {
			flt_ot_current_tracer->logging |= FLT_OT_LOGGING_ON;
		}
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_CONFIG) {
		retval = flt_ot_parse_cfg_file(&(flt_ot_current_tracer->config), file, linenum, args, &err, "configuration file");
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_PLUGIN) {
		retval = flt_ot_parse_cfg_file(&(flt_ot_current_tracer->plugin), file, linenum, args, &err, "plugin library");
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_GROUPS) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(i); i++)
			if (flt_ot_conf_ph_init(args[i], linenum, &(flt_ot_current_tracer->ph_groups), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_SCOPES) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(i); i++)
			if (flt_ot_conf_ph_init(args[i], linenum, &(flt_ot_current_tracer->ph_scopes), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_ACL) {
		if (strcasecmp(args[1], "or") == 0)
			FLT_OT_PARSE_ERR(&err, "'%s %s ...' : invalid ACL name", args[0], args[1]);
		else if (parse_acl((const char **)args + 1, &(flt_ot_current_tracer->acls), &err, &(flt_ot_current_config->proxy->conf.args), file, linenum) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_RATE_LIMIT) {
		flt_ot_current_tracer->rate_limit = FLT_OT_FLOAT_U32(flt_ot_strtod(args[1], 0.0, FLT_OT_RATE_LIMIT_MAX, &err), FLT_OT_RATE_LIMIT_MAX);
	}
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_OPTION) {
		if (strcmp(args[1], FLT_OT_PARSE_OPTION_DISABLED) == 0) {
			flt_ot_current_tracer->flag_disabled = (kw_mod == KWM_NO) ? 0 : 1;
		}
		else if (strcmp(args[1], FLT_OT_PARSE_OPTION_HARDERR) == 0) {
			flt_ot_current_tracer->flag_harderr = (kw_mod == KWM_NO) ? 0 : 1;
		}
		else if (strcmp(args[1], FLT_OT_PARSE_OPTION_NOLOGNORM) == 0) {
			if (kw_mod == KWM_NO)
				flt_ot_current_tracer->logging &= ~FLT_OT_LOGGING_NOLOGNORM;
			else
				flt_ot_current_tracer->logging |= FLT_OT_LOGGING_NOLOGNORM;
		}
		else
			FLT_OT_PARSE_ERR(&err, "'%s' : unknown option '%s'", args[0], args[1]);
	}
#ifdef DEBUG_OT
	else if (pdata->keyword == FLT_OT_PARSE_TRACER_DEBUG_LEVEL) {
		flt_ot_debug.level = flt_ot_strtoll(args[1], 0, 255, &err);
	}
#else
	else {
		FLT_OT_PARSE_WARNING("'%s' : keyword ignored", file, linenum, args[0]);
	}
#endif

	FLT_OT_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_ot_current_tracer != NULL))
		flt_ot_conf_tracer_free(&flt_ot_current_tracer);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_post_parse_cfg_tracer -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_post_parse_cfg_tracer(void)
{
	int retval = ERR_NONE;

	FLT_OT_FUNC("");

	if (flt_ot_current_tracer == NULL)
		FLT_OT_RETURN(retval);

	flt_ot_current_config->tracer = flt_ot_current_tracer;

	if (flt_ot_current_tracer->id == NULL)
		FLT_OT_RETURN(retval);

	if (flt_ot_current_tracer->config == NULL)
		FLT_OT_POST_PARSE_ALERT("tracer '%s' has no configuration file specified", flt_ot_current_tracer->cfg_line, flt_ot_current_tracer->id);

	if (flt_ot_current_tracer->plugin == NULL)
		FLT_OT_POST_PARSE_ALERT("tracer '%s' has no plugin library specified", flt_ot_current_tracer->cfg_line, flt_ot_current_tracer->id);

	flt_ot_current_tracer = NULL;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_group -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   kw_mod  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_group(const char *file, int linenum, char **args, int kw_mod)
{
#define FLT_OT_PARSE_GROUP_DEF(a,b,c,d,e,f,g)   { FLT_OT_PARSE_GROUP_##a, b, c, d, e, f, g },
	static const struct flt_ot_parse_data  parse_data[] = { FLT_OT_PARSE_GROUP_DEFINES };
#undef FLT_OT_PARSE_GROUP_DEF
	const struct flt_ot_parse_data        *pdata = NULL;
	char                                  *err = NULL;
	int                                    i, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, 0x%08x", file, linenum, args, kw_mod);

	if (flt_ot_parse_check_scope())
		FLT_OT_RETURN(retval);

	retval = flt_ot_parse_cfg_check(file, linenum, args, flt_ot_current_group, parse_data, FLT_OT_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OT_PARSE_IFERR_ALERT();

		FLT_OT_RETURN(retval);
	}

	if (pdata->keyword == FLT_OT_PARSE_GROUP_ID) {
		flt_ot_current_group = flt_ot_conf_group_init(args[1], linenum, &(flt_ot_current_config->groups), &err);
		if (flt_ot_current_config == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_GROUP_SCOPES) {
		for (i = 1; !(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(i); i++)
			if (flt_ot_conf_ph_init(args[i], linenum, &(flt_ot_current_group->ph_scopes), &err) == NULL)
				retval |= ERR_ABORT | ERR_ALERT;
	}

	FLT_OT_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_ot_current_group != NULL))
		flt_ot_conf_group_free(&flt_ot_current_group);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_post_parse_cfg_group -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_post_parse_cfg_group(void)
{
	int retval = ERR_NONE;

	FLT_OT_FUNC("");

	if (flt_ot_current_group == NULL)
		FLT_OT_RETURN(retval);

	/* Check that the group has at least one scope defined. */
	if (LIST_ISEMPTY(&(flt_ot_current_group->ph_scopes)))
		FLT_OT_POST_PARSE_ALERT("group '%s' has no defined scope(s)", flt_ot_current_group->cfg_line, flt_ot_current_group->id);

	flt_ot_current_group = NULL;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg_scope_ctx -
 *
 * ARGUMENTS
 *   args    -
 *   cur_arg -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_scope_ctx(char **args, int cur_arg, char **err)
{
	uint8_t flags = 0;
	int     retval = ERR_NONE;

	FLT_OT_FUNC("%p, %d, %p:%p", args, cur_arg, FLT_OT_DPTR_ARGS(err));

	if (strcmp(args[cur_arg], FLT_OT_PARSE_CTX_USE_HEADERS) == 0)
		flags = FLT_OT_CTX_USE_HEADERS;
	else if (strcmp(args[cur_arg], FLT_OT_PARSE_CTX_USE_VARS) == 0)
		flags = FLT_OT_CTX_USE_VARS;
	else
		FLT_OT_PARSE_ERR(err, "'%s' : invalid context storage type", args[0]);

	if (flags == 0)
		/* Do nothing. */;
	else if (flt_ot_current_span->ctx_flags & flags)
		FLT_OT_PARSE_ERR(err, "'%s' : %s already used", args[0], args[cur_arg]);
	else
		flt_ot_current_span->ctx_flags |= flags;

	FLT_OT_DBG(2, "ctx_flags: 0x%02hhx (0x%02hhx)", flt_ot_current_span->ctx_flags, flags);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_acl -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   px      -
 *   args    -
 *   err     -
 *   head    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static struct acl_cond *flt_ot_parse_acl(const char *file, int linenum, struct proxy *px, const char **args, char **err, struct list *head, ...)
{
	va_list          ap;
	int              n = 0;
	struct acl_cond *retptr = NULL;

	FLT_OT_FUNC("\"%s\", %d, %p, %p, %p:%p, %p, ...", file, linenum, px, args, FLT_OT_DPTR_ARGS(err), head);

	for (va_start(ap, head); (retptr == NULL) && (head != NULL); head = va_arg(ap, typeof(head)), n++) {
		retptr = build_acl_cond(file, linenum, head, px, args, (n == 0) ? err : NULL);
		if (retptr != NULL)
			FLT_OT_DBG(2, "ACL build done, using list %p %d", head, n);
	}
	va_end(ap);

	if ((retptr != NULL) && (err != NULL))
		FLT_OT_FREE_CLEAR(*err);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_parse_cfg_scope -
 *
 * ARGUMENTS
 *   file    -
 *   linenum -
 *   args    -
 *   kw_mod  -
 *
 * DESCRIPTION
 *   Function used to load the scope block configuration.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg_scope(const char *file, int linenum, char **args, int kw_mod)
{
#define FLT_OT_PARSE_SCOPE_DEF(a,b,c,d,e,f,g)   { FLT_OT_PARSE_SCOPE_##a, b, c, d, e, f, g },
	static const struct flt_ot_parse_data  parse_data[] = { FLT_OT_PARSE_SCOPE_DEFINES };
#undef FLT_OT_PARSE_SCOPE_DEF
	const struct flt_ot_parse_data        *pdata = NULL;
	char                                  *err = NULL;
	int                                    i, retval = ERR_NONE;

	FLT_OT_FUNC("\"%s\", %d, %p, 0x%08x", file, linenum, args, kw_mod);

	if (flt_ot_parse_check_scope())
		FLT_OT_RETURN(retval);

	retval = flt_ot_parse_cfg_check(file, linenum, args, flt_ot_current_span, parse_data, FLT_OT_TABLESIZE(parse_data), &pdata, &err);
	if (retval & ERR_CODE) {
		FLT_OT_PARSE_IFERR_ALERT();

		FLT_OT_RETURN(retval);
	}

	if (pdata->keyword == FLT_OT_PARSE_SCOPE_ID) {
		/* Initialization of a new scope. */
		flt_ot_current_scope = flt_ot_conf_scope_init(args[1], linenum, &(flt_ot_current_config->scopes), &err);
		if (flt_ot_current_scope == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_SPAN) {
		/*
		 * Checking if this is the beginning of the definition of
		 * a new span.
		 */
		if (flt_ot_current_span != NULL) {
			FLT_OT_DBG(3, "span '%s' (done)", flt_ot_current_span->id);

			flt_ot_current_span = NULL;
		}

		/* Initialization of a new span. */
		flt_ot_current_span = flt_ot_conf_span_init(args[1], linenum, &(flt_ot_current_scope->spans), &err);

		/*
		 * In case the span has a defined reference,
		 * the correctness of the arguments is checked here.
		 */
		if (flt_ot_current_span == NULL) {
			retval |= ERR_ABORT | ERR_ALERT;
		}
		else if (FLT_OT_ARG_ISVALID(2)) {
			for (i = 2; (i < pdata->args_max) && FLT_OT_ARG_ISVALID(i); i++)
				if (strcmp(args[i], FLT_OT_PARSE_SPAN_ROOT) == 0) {
					if (flt_ot_current_span->flag_root)
						FLT_OT_PARSE_ERR(&err, "'%s' : already set (use '%s%s')", args[i], pdata->name, pdata->usage);
					else
						flt_ot_current_span->flag_root = 1;
				}
				else if ((strcmp(args[i], FLT_OT_PARSE_SPAN_REF_CHILD) == 0) || (strcmp(args[i], FLT_OT_PARSE_SPAN_REF_FOLLOWS) == 0)) {
					if (!FLT_OT_ARG_ISVALID(i + 1)) {
						FLT_OT_PARSE_ERR(&err, "'%s' : too few arguments (use '%s%s')", args[i], pdata->name, pdata->usage);
					}
					else if (strcmp(args[i++], FLT_OT_PARSE_SPAN_REF_CHILD) == 0) {
						flt_ot_current_span->ref_type   = otc_span_reference_child_of;
						flt_ot_current_span->ref_id_len = strlen(args[i]);

						retval = flt_ot_parse_strdup(&(flt_ot_current_span->ref_id), args[i], &err, args[1]);
					}
					else {
						flt_ot_current_span->ref_type   = otc_span_reference_follows_from;
						flt_ot_current_span->ref_id_len = strlen(args[i]);

						retval = flt_ot_parse_strdup(&(flt_ot_current_span->ref_id), args[i], &err, args[1]);
					}
				}
				else {
					FLT_OT_PARSE_ERR(&err, "'%s' : invalid argument (use '%s%s')", args[i], pdata->name, pdata->usage);
				}
		}
		else {
			/*
			 * This is not a faulty configuration, only such a case
			 * will be logged.
			 */
			FLT_OT_DBG(3, "new span '%s' without reference", flt_ot_current_span->id);
		}
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_TAG) {
		retval = flt_ot_parse_cfg_sample(file, linenum, args, &(flt_ot_current_span->tags), &err);
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_LOG) {
		retval = flt_ot_parse_cfg_sample(file, linenum, args, &(flt_ot_current_span->logs), &err);
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_BAGGAGE) {
		retval = flt_ot_parse_cfg_sample(file, linenum, args, &(flt_ot_current_span->baggages), &err);
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_INJECT) {
		/*
		 * Automatic context name generation can be specified here
		 * if the contents of the FLT_OT_PARSE_CTX_AUTONAME macro
		 * are used as the name.  In that case, if the context is
		 * after a particular event, it gets its name; otherwise
		 * it gets the name of the current span.
		 */
		if (flt_ot_current_span->ctx_id != NULL)
			FLT_OT_PARSE_ERR(&err, "'%s' : only one context per span is allowed", args[1]);
		else if (strcmp(args[1], FLT_OT_PARSE_CTX_AUTONAME) != 0)
			retval = flt_ot_parse_strdup(&(flt_ot_current_span->ctx_id), args[1], &err, args[0]);
		else if (flt_ot_current_scope->event != FLT_OT_EVENT_REQ_NONE)
			retval = flt_ot_parse_strdup(&(flt_ot_current_span->ctx_id), flt_ot_event_data[flt_ot_current_scope->event].name, &err, args[0]);
		else
			retval = flt_ot_parse_strdup(&(flt_ot_current_span->ctx_id), flt_ot_current_span->id, &err, args[0]);

		if (flt_ot_current_span->ctx_id != NULL) {
			flt_ot_current_span->ctx_id_len = strlen(flt_ot_current_span->ctx_id);

			/*
			 * Here is checked the context storage type; which, if
			 * not explicitly specified, is set to HTTP headers.
			 *
			 * It is possible to use both types of context storage
			 * at the same time.
			 */
			if (FLT_OT_ARG_ISVALID(2)) {
				retval = flt_ot_parse_cfg_scope_ctx(args, 2, &err);
				if (!(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(3))
					retval = flt_ot_parse_cfg_scope_ctx(args, 3, &err);
			} else {
				flt_ot_current_span->ctx_flags = FLT_OT_CTX_USE_HEADERS;
			}
		}
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_EXTRACT) {
		struct flt_ot_conf_context *conf_ctx;

		/*
		 * Here is checked the context storage type; which, if
		 * not explicitly specified, is set to HTTP headers.
		 */
		conf_ctx = flt_ot_conf_context_init(args[1], linenum, &(flt_ot_current_scope->contexts), &err);
		if (conf_ctx == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
		else if (!FLT_OT_ARG_ISVALID(2))
			conf_ctx->flags = FLT_OT_CTX_USE_HEADERS;
		else if (strcmp(args[2], FLT_OT_PARSE_CTX_USE_HEADERS) == 0)
			conf_ctx->flags = FLT_OT_CTX_USE_HEADERS;
		else if (strcmp(args[2], FLT_OT_PARSE_CTX_USE_VARS) == 0)
			conf_ctx->flags = FLT_OT_CTX_USE_VARS;
		else
			FLT_OT_PARSE_ERR(&err, "'%s' : invalid context storage type", args[2]);
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_FINISH) {
		retval = flt_ot_parse_cfg_str(file, linenum, args, &(flt_ot_current_scope->finish), &err);
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_ACL) {
		if (strcasecmp(args[1], "or") == 0)
			FLT_OT_PARSE_ERR(&err, "'%s %s ...' : invalid ACL name", args[0], args[1]);
		else if (parse_acl((const char **)args + 1, &(flt_ot_current_scope->acls), &err, &(flt_ot_current_config->proxy->conf.args), file, linenum) == NULL)
			retval |= ERR_ABORT | ERR_ALERT;
	}
	else if (pdata->keyword == FLT_OT_PARSE_SCOPE_EVENT) {
		/* Scope can only have one event defined. */
		if (flt_ot_current_scope->event != FLT_OT_EVENT_REQ_NONE) {
			FLT_OT_PARSE_ERR(&err, "'%s' : event already set", flt_ot_current_scope->id);
		} else {
			/* Check the event name. */
			for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_event_data); i++)
				if (strcmp(flt_ot_event_data[i].name, args[1]) == 0) {
					flt_ot_current_scope->event = i;

					break;
				}

			/*
			 * The event can have some condition defined and this
			 * is checked here.
			 */
			if (flt_ot_current_scope->event == FLT_OT_EVENT_REQ_NONE) {
				FLT_OT_PARSE_ERR(&err, "'%s' : unknown event", args[1]);
			}
			else if (!FLT_OT_ARG_ISVALID(2)) {
				/* Do nothing. */
			}
			else if ((strcmp(args[2], FLT_OT_CONDITION_IF) == 0) || (strcmp(args[2], FLT_OT_CONDITION_UNLESS) == 0)) {
				/*
				 * We will first try to build ACL condition using
				 * local settings and then if that fails, using
				 * global settings (from tracer block).  If it
				 * also fails, then try to use ACL defined in
				 * the HAProxy configuration.
				 */
				flt_ot_current_scope->cond = flt_ot_parse_acl(file, linenum, flt_ot_current_config->proxy, (const char **)args + 2, &err, &(flt_ot_current_scope->acls), &(flt_ot_current_config->tracer->acls), &(flt_ot_current_config->proxy->acl), NULL);
				if (flt_ot_current_scope->cond == NULL)
					retval |= ERR_ABORT | ERR_ALERT;
			}
			else {
				FLT_OT_PARSE_ERR(&err, "'%s' : expects either 'if' or 'unless' followed by a condition but found '%s'", args[1], args[2]);
			}

			if (!(retval & ERR_CODE))
				FLT_OT_DBG(3, "event '%s'", args[1]);
		}
	}

	FLT_OT_PARSE_IFERR_ALERT();

	if ((retval & ERR_CODE) && (flt_ot_current_scope != NULL)) {
		flt_ot_conf_scope_free(&flt_ot_current_scope);

		flt_ot_current_span = NULL;
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_post_parse_cfg_scope -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   In this function the correctness of the complete scope block is examined.
 *   This does not mean that all elements are checked here, but only those for
 *   which it has not been possible to establish their complete correctness in
 *   the function flt_ot_parse_cfg_scope().
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_post_parse_cfg_scope(void)
{
	struct flt_ot_conf_span *conf_span;
	int                      retval = ERR_NONE;

	FLT_OT_FUNC("");

	if (flt_ot_current_scope == NULL)
		FLT_OT_RETURN(retval);

	/* If span context inject is used, check that this is possible. */
	list_for_each_entry(conf_span, &(flt_ot_current_scope->spans), list)
		if ((conf_span->ctx_id != NULL) && (conf_span->ctx_flags & FLT_OT_CTX_USE_HEADERS))
			if (!flt_ot_event_data[flt_ot_current_scope->event].flag_http_inject)
				FLT_OT_POST_PARSE_ALERT("inject '%s' : cannot use on this event", conf_span->cfg_line, conf_span->ctx_id);

	if (retval & ERR_CODE)
		flt_ot_conf_scope_free(&flt_ot_current_scope);

	flt_ot_current_scope = NULL;
	flt_ot_current_span  = NULL;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse_cfg -
 *
 * ARGUMENTS
 *   conf     -
 *   flt_name -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse_cfg(struct flt_ot_conf *conf, const char *flt_name, char **err)
{
	struct list backup_sections;
	int         retval = ERR_ABORT | ERR_ALERT;

	FLT_OT_FUNC("%p, \"%s\", %p:%p", conf, flt_name, FLT_OT_DPTR_ARGS(err));

	flt_ot_current_config = conf;

	/* Backup sections. */
	LIST_INIT(&backup_sections);
	cfg_backup_sections(&backup_sections);

	/* Register new OT sections and parse the OT filter configuration file. */
	if (!cfg_register_section(FLT_OT_PARSE_SECTION_TRACER_ID, flt_ot_parse_cfg_tracer, flt_ot_post_parse_cfg_tracer))
		/* Do nothing. */;
	else if (!cfg_register_section(FLT_OT_PARSE_SECTION_GROUP_ID, flt_ot_parse_cfg_group, flt_ot_post_parse_cfg_group))
		/* Do nothing. */;
	else if (!cfg_register_section(FLT_OT_PARSE_SECTION_SCOPE_ID, flt_ot_parse_cfg_scope, flt_ot_post_parse_cfg_scope))
		/* Do nothing. */;
	else if (access(conf->cfg_file, R_OK) == -1)
		FLT_OT_PARSE_ERR(err, "'%s' : %s", conf->cfg_file, strerror(errno));
	else
		retval = readcfgfile(conf->cfg_file);

	/* Unregister OT sections and restore previous sections. */
	cfg_unregister_sections();
	cfg_restore_sections(&backup_sections);

	flt_ot_current_config = NULL;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_parse -
 *
 * ARGUMENTS
 *   args    -
 *   cur_arg -
 *   px      -
 *   fconf   -
 *   err     -
 *   private -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_ot_parse(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf, char **err, void *private)
{
	struct flt_ot_conf *conf = NULL;
	int                 pos, retval = ERR_NONE;

#ifdef DEBUG_OT
	FLT_OT_RUN_ONCE(
#  ifndef DEBUG_OT_SYSTIME
		(void)memcpy(&(flt_ot_debug.start), &now, sizeof(flt_ot_debug.start));
#  endif

		flt_ot_debug.level = FLT_OT_DEBUG_LEVEL;
	);
#endif

	FLT_OT_FUNC("%p, %p, %p, %p, %p:%p, %p", args, cur_arg, px, fconf, FLT_OT_DPTR_ARGS(err), private);

#ifdef OTC_DBG_MEM
	FLT_OT_RUN_ONCE(
		if (otc_dbg_mem_init(&dbg_mem, dbg_mem_data, FLT_OT_TABLESIZE(dbg_mem_data), 0xff) == -1) {
			FLT_OT_PARSE_ERR(err, "cannot initialize memory debugger");

			FLT_OT_RETURN(retval);
		}
	);
#endif

	FLT_OT_ARGS_DUMP();

	conf = flt_ot_conf_init(px);
	if (conf == NULL) {
		FLT_OT_PARSE_ERR(err, "'%s' : out of memory", args[*cur_arg]);

		FLT_OT_RETURN(retval);
	}

	for (pos = *cur_arg + 1; !(retval & ERR_CODE) && FLT_OT_ARG_ISVALID(pos); pos++) {
		FLT_OT_DBG(3, "args[%d:2] : { '%s' '%s' }", pos, args[pos], args[pos + 1]);

		if (strcmp(args[pos], FLT_OT_OPT_FILTER_ID) == 0) {
			retval = flt_ot_parse_keyword(&(conf->id), args, *cur_arg, pos, err, "name");
			pos++;
		}
		else if (strcmp(args[pos], FLT_OT_OPT_CONFIG) == 0) {
			retval = flt_ot_parse_keyword(&(conf->cfg_file), args, *cur_arg, pos, err, "configuration file");
			if (!(retval & ERR_CODE))
				retval = flt_ot_parse_cfg(conf, args[*cur_arg], err);
			pos++;
		}
		else {
			FLT_OT_PARSE_ERR(err, "'%s' : unknown keyword '%s'", args[*cur_arg], args[pos]);
		}
	}

	/* If the OpenTracing filter ID is not set, use default name. */
	if (!(retval & ERR_CODE) && (conf->id == NULL)) {
		ha_warning("parsing : " FLT_OT_FMT_TYPE FLT_OT_FMT_NAME "'no filter id set, using default id '%s'\n", FLT_OT_OPT_FILTER_ID_DEFAULT);

		retval = flt_ot_parse_strdup(&(conf->id), FLT_OT_OPT_FILTER_ID_DEFAULT, err, args[*cur_arg]);
	}

	if (!(retval & ERR_CODE) && (conf->cfg_file == NULL))
		FLT_OT_PARSE_ERR(err, "'%s' : no configuration file specified", args[*cur_arg]);

	if (retval & ERR_CODE) {
		flt_ot_conf_free(&conf);
	} else {
		fconf->id   = ot_flt_id;
		fconf->ops  = &flt_ot_ops;
		fconf->conf = conf;

		*cur_arg = pos;

		FLT_OT_DBG(3, "filter set: id '%s', config '%s'", conf->id, conf->cfg_file);
	}

	FLT_OT_RETURN(retval);
}


/* Declare the filter parser for FLT_OT_OPT_NAME keyword. */
static struct flt_kw_list flt_kws = { FLT_OT_SCOPE, { }, {
		{ FLT_OT_OPT_NAME, flt_ot_parse, NULL },
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
