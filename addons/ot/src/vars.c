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
 *   Function prints the contents of all variables defined for a particular
 *   scope.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_ot_vars_scope_dump(struct vars *vars, const char *scope)
{
	const struct var *var;

	if (vars == NULL)
		return;

	vars_rdlock(vars);
	list_for_each_entry(var, &(vars->head), l)
		FLT_OT_DBG(2, "'%s.%s' -> '%.*s'", scope, var->name, (int)var->data.u.str.data, var->data.u.str.area);
	vars_rdunlock(vars);
}


/***
 * NAME
 *   flt_ot_vars_dump -
 *
 * ARGUMENTS
 *   s -
 *
 * DESCRIPTION
 *   Function prints the contents of all variables grouped by individual
 *   scope.
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
	flt_ot_vars_scope_dump(&(proc_vars), "PROC");
	flt_ot_vars_scope_dump(&(s->sess->vars), "SESS");
	flt_ot_vars_scope_dump(&(s->vars_txn), "TXN");
	flt_ot_vars_scope_dump(&(s->vars_reqres), "REQ/RES");

	FLT_OT_RETURN();
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_smp_init -
 *
 * ARGUMENTS
 *   s    -
 *   smp  -
 *   opt  -
 *   type -
 *   data -
 *
 * DESCRIPTION
 *   The function initializes the value of the 'smp' structure.  If the 'data'
 *   argument is set, then the 'sample_data' member of the 'smp' structure is
 *   also initialized.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static inline void flt_ot_smp_init(struct stream *s, struct sample *smp, uint opt, int type, const char *data)
{
	(void)memset(smp, 0, sizeof(*smp));
	(void)smp_set_owner(smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);

	if (data != NULL) {
		smp->data.type = type;

		chunk_initstr(&(smp->data.u.str), data);
	}
}


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
 *   Returns the struct vars pointer for a stream and scope, or NULL if it does
 *   not exist.
 */
static inline struct vars *flt_ot_get_vars(struct stream *s, const char *scope)
{
	struct vars *retptr = NULL;

	if (strcasecmp(scope, "proc") == 0)
		retptr = &(proc_vars);
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
 *   flag_cpy -
 *   err      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_normalize_name(char *var_name, size_t size, int *len, const char *name, bool flag_cpy, char **err)
{
	int retval = 0;

	FLT_OT_FUNC("%p, %zu, %p, \"%s\", %hhu, %p:%p", var_name, size, len, name, flag_cpy, FLT_OT_DPTR_ARGS(err));

	if (!FLT_OT_STR_ISVALID(name))
		FLT_OT_RETURN_INT(retval);

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

	if (flag_cpy) {
		retval = strlen(name);
		if ((*len + retval + 1) > size) {
			FLT_OT_ERR("failed to normalize variable name, buffer too small");

			retval = -1;
		} else {
			(void)memcpy(var_name + *len, name, retval + 1);
			*len += retval;
		}
	} else {
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
	}

	FLT_OT_DBG(3, "var_name: \"%s\" %d/%d", var_name, retval, *len);

	if (retval == -1)
		*len = retval;

	FLT_OT_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_ot_var_name -
 *
 * ARGUMENTS
 *   scope    -
 *   prefix   -
 *   name     -
 *   flag_cpy -
 *   var_name -
 *   size     -
 *   err      -
 *
 * DESCRIPTION
 *   The function initializes the value of the 'smp' structure.  If the 'data'
 *   argument is set, then the 'sample_data' member of the 'smp' structure is
 *   also initialized.
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_var_name(const char *scope, const char *prefix, const char *name, bool flag_cpy, char *var_name, size_t size, char **err)
{
	int retval = 0;

	FLT_OT_FUNC("\"%s\", \"%s\", \"%s\", %hhu, %p, %zu, %p:%p", scope, prefix, name, flag_cpy, var_name, size, FLT_OT_DPTR_ARGS(err));

	if (flt_ot_normalize_name(var_name, size, &retval, scope, 0, err) >= 0)
		if (flt_ot_normalize_name(var_name, size, &retval, prefix, 0, err) >= 0)
			(void)flt_ot_normalize_name(var_name, size, &retval, name, flag_cpy, err);

	if (retval == -1)
		FLT_OT_ERR("failed to construct variable name '%s.%s.%s'", scope, prefix, name);

	FLT_OT_RETURN_INT(retval);
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
	int        retval = -1, var_name_len;

	FLT_OT_FUNC("\"%s\", \"%s\", \"%s\", %p:%p", scope, prefix, name, FLT_OT_DPTR_ARGS(err));

	var_name_len = flt_ot_var_name(scope, prefix, name, 0, var_name, sizeof(var_name), err);
	if (var_name_len == -1)
		FLT_OT_RETURN_INT(retval);

	/* Set <size> to 0 to not release var_name memory in vars_check_arg(). */
	(void)memset(&arg, 0, sizeof(arg));
	arg.type          = ARGT_STR;
	arg.data.str.area = var_name;
	arg.data.str.data = var_name_len;

	if (vars_check_arg(&arg, err) == 0) {
		FLT_OT_ERR_APPEND("failed to register variable '%s': %s", var_name, *err);
	} else {
		FLT_OT_DBG(2, "variable '%s' registered", arg.data.var.name);

		retval = var_name_len;
	}

	FLT_OT_RETURN_INT(retval);
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
	int           retval = -1, var_name_len;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, name, value, opt, FLT_OT_DPTR_ARGS(err));

	var_name_len = flt_ot_var_name(scope, prefix, name, 0, var_name, sizeof(var_name), err);
	if (var_name_len == -1)
		FLT_OT_RETURN_INT(retval);

	flt_ot_smp_init(s, &smp, opt, SMP_T_STR, value);

	if (vars_set_by_name_ifexist(var_name, var_name_len, &smp) == 0) {
		FLT_OT_ERR("failed to set variable '%s'", var_name);
	} else {
		FLT_OT_DBG(2, "variable '%s' set", var_name);

		retval = var_name_len;
	}

	FLT_OT_RETURN_INT(retval);
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
		FLT_OT_RETURN_INT(retval);

	var_prefix_len = flt_ot_var_name(NULL, prefix, NULL, 0, var_prefix, sizeof(var_prefix), err);
	if (var_prefix_len == -1)
		FLT_OT_RETURN_INT(retval);

	retval = 0;

	vars_wrlock(vars);
	list_for_each_entry_safe(var, var_back, &(vars->head), l) {
		FLT_OT_DBG(3, "variable cmp '%s' '%s' %d", var_prefix, var->name, var_prefix_len);

		if (strncmp(var_prefix, var->name, var_prefix_len) == 0) {
			var_name_len = snprintf(var_name, sizeof(var_name), "%s.%s", scope, var->name);
			if ((var_name_len == -1) || (var_name_len >= sizeof(var_name))) {
				FLT_OT_DBG(2, "'%s.%s' variable name too long", scope, var->name);

				break;
			}

			FLT_OT_DBG(2, "- '%s' -> '%.*s'", var_name, (int)var->data.u.str.data, var->data.u.str.area);

			size = var_clear(var, 1);
			flt_ot_smp_init(s, &smp, opt, 0, NULL);
			var_accounting_diff(vars, smp.sess, smp.strm, -size);

			retval++;
		}
	}
	vars_wrunlock(vars);

	FLT_OT_RETURN_INT(retval);
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
		FLT_OT_RETURN_PTR(retptr);

	rc = flt_ot_var_name(NULL, prefix, NULL, 0, var_name, sizeof(var_name), err);
	if (rc == -1)
		FLT_OT_RETURN_PTR(retptr);

	vars_rdlock(vars);
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
	vars_rdunlock(vars);

	ot_text_map_show(retptr);

	if ((retptr != NULL) && (retptr->count == 0)) {
		FLT_OT_DBG(2, "WARNING: no variables found");

		otc_text_map_destroy(&retptr, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);
	}

	FLT_OT_RETURN_PTR(retptr);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
