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

/***
 * NAME
 *   flt_ot_vars_scope_dump -
 *
 * ARGUMENTS
 *   vars  -
 *   scope -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_vars_scope_dump(struct vars *vars, const char *scope)
{
	const struct var *var;

	if (vars == NULL)
		return;

	HA_RWLOCK_RDLOCK(VARS_LOCK, &(vars->rwlock));
	list_for_each_entry(var, &(vars->head), l)
		FLT_OT_DBG(2, "'%s.%s' -> '%.*s'", scope, var->name, (int)var->data.u.str.data, var->data.u.str.area);
	HA_RWLOCK_RDUNLOCK(VARS_LOCK, &(vars->rwlock));
}


/***
 * NAME
 *   flt_ot_vars_dump -
 *
 * ARGUMENTS
 *   s -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_vars_dump(struct stream *s)
{
	FLT_OT_FUNC("%p", s);

	/*
	 * It would be nice if we could use the get_vars() function from HAProxy
	 * source here to get the value of the 'vars' pointer, but it is defined
	 * as 'static inline', so unfortunately none of this is possible.
	 */
	flt_ot_vars_scope_dump(&(global.vars), "PROC");
	flt_ot_vars_scope_dump(&(s->sess->vars), "SESS");
	flt_ot_vars_scope_dump(&(s->vars_txn), "TXN");
	flt_ot_vars_scope_dump(&(s->vars_reqres), "REQ/RES");

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_get_vars -
 *
 * ARGUMENTS
 *   s     -
 *   scope -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static inline struct vars *flt_ot_get_vars(struct stream *s, const char *scope)
{
	struct vars *retptr = NULL;

	if (strcasecmp(scope, "proc") == 0)
		retptr = &(global.vars);
	else if (strcasecmp(scope, "sess") == 0)
		retptr = (&(s->sess->vars));
	else if (strcasecmp(scope, "txn") == 0)
		retptr = (&(s->vars_txn));
	else if ((strcasecmp(scope, "req") == 0) || (strcasecmp(scope, "res") == 0))
		retptr = (&(s->vars_reqres));

	return retptr;
}


/***
 * NAME
 *   flt_ot_normalize_name -
 *
 * ARGUMENTS
 *   var_name -
 *   size     -
 *   len      -
 *   name     -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_normalize_name(char *var_name, size_t size, int *len, const char *name, char **err)
{
	int retval = 0;

	FLT_OT_FUNC("%p, %zu, %p, \"%s\", %p:%p", var_name, size, len, name, FLT_OT_DPTR_ARGS(err));

	if (!FLT_OT_STR_ISVALID(name))
		FLT_OT_RETURN(retval);

	/*
	 * In case the name of the variable consists of several elements,
	 * the character '.' is added between them.
	 */
	if ((*len == 0) || (var_name[*len - 1] == '.'))
		/* Do nothing. */;
	else if (*len < (size - 1))
		var_name[(*len)++] = '.';
	else
		retval = -1;

	/*
	 * HAProxy does not allow the use of variable names containing '-'
	 * or ' '.  This of course applies to HTTP header names as well.
	 * Also, here the capital letters are converted to lowercase.
	 */
	while (retval != -1)
		if (*len >= (size - 1)) {
			FLT_OT_ERR("failed to normalize variable name, buffer too small");

			retval = -1;
		} else {
			uint8_t ch = name[retval];

			if (ch == '\0')
				break;
			else if (ch == '-')
				ch = FLT_OT_VAR_CHAR_DASH;
			else if (ch == ' ')
				ch = FLT_OT_VAR_CHAR_SPACE;
			else if (isupper(ch))
				ch = ist_lc[ch];

			var_name[(*len)++] = ch;
			retval++;
		}

	var_name[*len] = '\0';

	FLT_OT_DBG(3, "var_name: \"%s\" %d/%d", var_name, retval, *len);

	if (retval == -1)
		*len = retval;

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_var_name -
 *
 * ARGUMENTS
 *   scope    -
 *   prefix   -
 *   name     -
 *   var_name -
 *   size     -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_var_name(const char *scope, const char *prefix, const char *name, char *var_name, size_t size, char **err)
{
	int retval = 0;

	FLT_OT_FUNC("\"%s\", \"%s\", \"%s\", %p, %zu, %p:%p", scope, prefix, name, var_name, size, FLT_OT_DPTR_ARGS(err));

	if (flt_ot_normalize_name(var_name, size, &retval, scope, err) >= 0)
		if (flt_ot_normalize_name(var_name, size, &retval, prefix, err) >= 0)
			(void)flt_ot_normalize_name(var_name, size, &retval, name, err);

	if (retval == -1)
		FLT_OT_ERR("failed to construct variable name '%s.%s.%s'", scope, prefix, name);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_var_register -
 *
 * ARGUMENTS
 *   scope  -
 *   prefix -
 *   name   -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_var_register(const char *scope, const char *prefix, const char *name, char **err)
{
	struct arg arg;
	char       var_name[BUFSIZ];
	int        retval;

	FLT_OT_FUNC("\"%s\", \"%s\", \"%s\", %p:%p", scope, prefix, name, FLT_OT_DPTR_ARGS(err));

	retval = flt_ot_var_name(scope, prefix, name, var_name, sizeof(var_name), err);
	if (retval == -1)
		FLT_OT_RETURN(retval);

	/* Set <size> to 0 to not release var_name memory in vars_check_arg(). */
	(void)memset(&arg, 0, sizeof(arg));
	arg.type          = ARGT_STR;
	arg.data.str.area = var_name;
	arg.data.str.data = retval;

	if (vars_check_arg(&arg, err) == 0) {
		FLT_OT_ERR_APPEND("failed to register variable '%s': %s", var_name, *err);

		retval = -1;
	} else {
		FLT_OT_DBG(2, "variable '%s' registered", arg.data.var.name);
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_var_set -
 *
 * ARGUMENTS
 *   s      -
 *   scope  -
 *   prefix -
 *   name   -
 *   value  -
 *   opt    -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_var_set(struct stream *s, const char *scope, const char *prefix, const char *name, const char *value, uint opt, char **err)
{
	struct sample smp;
	char          var_name[BUFSIZ];
	int           retval;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, name, value, opt, FLT_OT_DPTR_ARGS(err));

	retval = flt_ot_var_name(scope, prefix, name, var_name, sizeof(var_name), err);
	if (retval == -1)
		FLT_OT_RETURN(retval);

	(void)memset(&smp, 0, sizeof(smp));
	(void)smp_set_owner(&smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);
	smp.data.type       = SMP_T_STR;
	smp.data.u.str.area = (char *)value;
	smp.data.u.str.data = strlen(value);

	vars_set_by_name_ifexist(var_name, retval, &smp);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_var_unset -
 *
 * ARGUMENTS
 *   s      -
 *   scope  -
 *   prefix -
 *   name   -
 *   opt    -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_var_unset(struct stream *s, const char *scope, const char *prefix, const char *name, uint opt, char **err)
{
	struct sample smp;
	char          var_name[BUFSIZ];
	int           retval;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, name, opt, FLT_OT_DPTR_ARGS(err));

	retval = flt_ot_var_name(scope, prefix, name, var_name, sizeof(var_name), err);
	if (retval == -1)
		FLT_OT_RETURN(retval);

	(void)memset(&smp, 0, sizeof(smp));
	(void)smp_set_owner(&smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);

	vars_unset_by_name_ifexist(var_name, retval, &smp);

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_vars_unset -
 *
 * ARGUMENTS
 *   s      -
 *   scope  -
 *   prefix -
 *   opt    -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct sample  smp;
	struct vars   *vars;
	struct var    *var, *var_back;
	char           var_prefix[BUFSIZ], var_name[BUFSIZ];
	uint           size;
	int            var_prefix_len, var_name_len, retval = -1;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, opt, FLT_OT_DPTR_ARGS(err));

	vars = flt_ot_get_vars(s, scope);
	if (vars == NULL)
		FLT_OT_RETURN(retval);

	var_prefix_len = flt_ot_var_name(NULL, prefix, NULL, var_prefix, sizeof(var_prefix), err);
	if (var_prefix_len == -1)
		FLT_OT_RETURN(retval);

	retval = 0;

	HA_RWLOCK_WRLOCK(VARS_LOCK, &(vars->rwlock));
	list_for_each_entry_safe(var, var_back, &(vars->head), l) {
		FLT_OT_DBG(3, "variable cmp '%s' '%s' %d", var_prefix, var->name, var_prefix_len);

		if (strncmp(var_prefix, var->name, var_prefix_len) == 0) {
			var_name_len = snprintf(var_name, sizeof(var_name), "%s.%s", scope, var->name);
			if ((var_name_len == -1) || (var_name_len >= sizeof(var_name))) {
				FLT_OT_DBG(2, "'%s.%s' variable name too long", scope, var->name);

				break;
			}

			FLT_OT_DBG(2, "- '%s' -> '%.*s'", var_name, (int)var->data.u.str.data, var->data.u.str.area);

			(void)memset(&smp, 0, sizeof(smp));
			(void)smp_set_owner(&smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);

			size = var_clear(var);
			var_accounting_diff(vars, smp.sess, smp.strm, -size);

			retval++;
		}
	}
	HA_RWLOCK_WRUNLOCK(VARS_LOCK, &(vars->rwlock));

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_var_get -
 *
 * ARGUMENTS
 *   s      -
 *   scope  -
 *   prefix -
 *   name   -
 *   value  -
 *   opt    -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_var_get(struct stream *s, const char *scope, const char *prefix, const char *name, char **value, uint opt, char **err)
{
	struct sample smp;
	char          var_name[BUFSIZ], var_value[BUFSIZ];
	int           retval;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", %p:%p, %u, %p:%p", s, scope, prefix, name, FLT_OT_DPTR_ARGS(value), opt, FLT_OT_DPTR_ARGS(err));

	retval = flt_ot_var_name(scope, prefix, name, var_name, sizeof(var_name), err);
	if (retval == -1)
		FLT_OT_RETURN(retval);

	(void)memset(&smp, 0, sizeof(smp));
	(void)smp_set_owner(&smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);

	if (vars_get_by_name(var_name, retval, &smp)) {
		retval = flt_ot_sample_to_str(&(smp.data), var_value, sizeof(var_value), err);
		if (retval != -1)
			FLT_OT_DBG(3, "data type %d: '%s' = '%s'", smp.data.type, var_name, var_value);
	} else {
		FLT_OT_ERR("failed to get variable '%s'", var_name);

		retval = -1;
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_vars_get -
 *
 * ARGUMENTS
 *   s      -
 *   scope  -
 *   prefix -
 *   opt    -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct otc_text_map *flt_ot_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct vars         *vars;
	const struct var    *var;
	char                 var_name[BUFSIZ], ot_var_name[BUFSIZ];
	int                  rc, i;
	struct otc_text_map *retptr = NULL;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, opt, FLT_OT_DPTR_ARGS(err));

	vars = flt_ot_get_vars(s, scope);
	if (vars == NULL)
		FLT_OT_RETURN(retptr);

	rc = flt_ot_var_name(NULL, prefix, NULL, var_name, sizeof(var_name), err);
	if (rc == -1)
		FLT_OT_RETURN(retptr);

	HA_RWLOCK_RDLOCK(VARS_LOCK, &(vars->rwlock));
	list_for_each_entry(var, &(vars->head), l) {
		FLT_OT_DBG(3, "variable cmp '%s' '%s' %d", var_name, var->name, rc);

		if (strncmp(var_name, var->name, rc) == 0) {
			FLT_OT_DBG(2, "'%s.%s' -> '%.*s'", scope, var->name, (int)var->data.u.str.data, var->data.u.str.area);

			if (retptr == NULL) {
				retptr = otc_text_map_new(NULL, 8);
				if (retptr == NULL) {
					FLT_OT_ERR("failed to create data");

					break;
				}
			}

			/*
			 * Eh, because the use of some characters is not allowed
			 * in the variable name, the conversion of the replaced
			 * characters to the original is performed here.
			 */
			for (i = 0; ; )
				if (i >= (FLT_OT_TABLESIZE(ot_var_name) - 1)) {
					FLT_OT_ERR("failed to reverse variable name, buffer too small");

					otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);

					break;
				} else {
					char ch = var->name[rc + i + 1];

					if (ch == '\0')
						break;
					else if (ch == FLT_OT_VAR_CHAR_DASH)
						ch = '-';
					else if (ch == FLT_OT_VAR_CHAR_SPACE)
						ch = ' ';

					ot_var_name[i++] = ch;
				}
			ot_var_name[i] = '\0';

			if (retptr == NULL) {
				break;
			}
			else if (otc_text_map_add(retptr, ot_var_name, i, var->data.u.str.area, var->data.u.str.data, OTC_TEXT_MAP_DUP_KEY | OTC_TEXT_MAP_DUP_VALUE) == -1) {
				FLT_OT_ERR("failed to add map data");

				otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);

				break;
			}
		}
	}
	HA_RWLOCK_RDUNLOCK(VARS_LOCK, &(vars->rwlock));

	ot_text_map_show(retptr);

	if ((retptr != NULL) && (retptr->count == 0)) {
		FLT_OT_DBG(2, "WARNING: no variables found");

		otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);
	}

	FLT_OT_RETURN(retptr);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
