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
	int i;

	if (vars == NULL)
		return;

	vars_rdlock(vars);
	for (i = 0; i < VAR_NAME_ROOTS; i++) {
		struct ceb_node *node = cebu64_first(&(vars->name_root[i]));

		for ( ; node != NULL; node = cebu64_next(&(vars->name_root[i]), node)) {
			struct var *var = container_of(node, struct var, node);

			FLT_OT_DBG(2, "'%s.%016" PRIx64 "' -> '%.*s'", scope, var->name_hash, (int)b_data(&(var->data.u.str)), b_orig(&(var->data.u.str)));
		}
	}
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
 *   flt_ot_smp_add -
 *
 * ARGUMENTS
 *   data -
 *   blk  -
 *   len  -
 *   err  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_smp_add(struct sample_data *data, const char *name, size_t len, char **err)
{
	bool flag_alloc = 0;
	int  retval = FLT_OT_RET_ERROR;

	FLT_OT_FUNC("%p, \"%.*s\", %zu, %p:%p", data, (int)len, name, len, FLT_OT_DPTR_ARGS(err));

	FLT_OT_DBG_BUF(2, &(data->u.str));

	if (b_orig(&(data->u.str)) == NULL) {
		data->type = SMP_T_BIN;
		chunk_init(&(data->u.str), FLT_OT_MALLOC(global.tune.bufsize), global.tune.bufsize);

		flag_alloc = (b_orig(&(data->u.str)) != NULL);
	}

	if (b_orig(&(data->u.str)) == NULL) {
		FLT_OT_ERR("failed to add ctx '%.*s', not enough memory", (int)len, name);
	}
	else if (len > ((UINT64_C(1) << ((sizeof(FLT_OT_VAR_CTX_SIZE) << 3) - 1)) - 1)) {
		FLT_OT_ERR("failed to add ctx '%.*s', too long name", (int)len, name);
	}
	else if ((len + sizeof(FLT_OT_VAR_CTX_SIZE)) > b_room(&(data->u.str))) {
		FLT_OT_ERR("failed to add ctx '%.*s', too many names", (int)len, name);
	}
	else {
		retval = b_data(&(data->u.str));

		b_putchr(&(data->u.str), len);
		(void)__b_putblk(&(data->u.str), name, len);

		FLT_OT_DBG_BUF(2, &(data->u.str));
	}

	if ((retval == FLT_OT_RET_ERROR) && flag_alloc)
		FLT_OT_FREE(b_orig(&(data->u.str)));

	FLT_OT_RETURN_INT(retval);
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
	else {
		FLT_OT_ERR("failed to normalize variable name, buffer too small");

		retval = -1;
	}

	if (flag_cpy) {
		/* Copy variable name without modification. */
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
 *   flt_ot_ctx_loop -
 *
 * ARGUMENTS
 *   smp    -
 *   scope  -
 *   prefix -
 *   err    -
 *   func   -
 *   ptr    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_ctx_loop(struct sample *smp, const char *scope, const char *prefix, char **err, flt_ot_ctx_loop_cb func, void *ptr)
{
	FLT_OT_VAR_CTX_SIZE var_ctx_size;
	char                var_name[BUFSIZ], var_ctx[BUFSIZ];
	int                 i, var_name_len, var_ctx_len, rc, n = 1, retval = 0;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", %p:%p, %p, %p", smp, scope, prefix, FLT_OT_DPTR_ARGS(err), func, ptr);

	/*
	 * The variable in which we will save the name of the OpenTracing
	 * context variable.
	 */
	var_name_len = flt_ot_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
	if (var_name_len == -1)
		FLT_OT_RETURN_INT(FLT_OT_RET_ERROR);

	/*
	 * Here we will try to find all the previously recorded variables from
	 * the currently set OpenTracing context.  If we find the required
	 * variable and it is marked as deleted, we will mark it as active.
	 * If we do not find it, then it is added to the end of the previously
	 * saved names.
	 */
	if (vars_get_by_name(var_name, var_name_len, smp, NULL) == 0) {
		FLT_OT_DBG(2, "ctx '%s' no variable found", var_name);
	}
	else if (smp->data.type != SMP_T_BIN) {
		FLT_OT_ERR("ctx '%s' invalid data type %d", var_name, smp->data.type);

		retval = FLT_OT_RET_ERROR;
	}
	else {
		FLT_OT_DBG_BUF(2, &(smp->data.u.str));

		for (i = 0; i < b_data(&(smp->data.u.str)); i += sizeof(var_ctx_size) + var_ctx_len, n++) {
			var_ctx_size = *((typeof(var_ctx_size) *)(b_orig(&(smp->data.u.str)) + i));
			var_ctx_len  = abs(var_ctx_size);

			if ((i + sizeof(var_ctx_size) + var_ctx_len) > b_data(&(smp->data.u.str))) {
				FLT_OT_ERR("ctx '%s' invalid data size", var_name);

				retval = FLT_OT_RET_ERROR;

				break;
			}

			(void)memcpy(var_ctx, b_orig(&(smp->data.u.str)) + i + sizeof(var_ctx_size), var_ctx_len);
			var_ctx[var_ctx_len] = '\0';

			rc = func(smp, i, scope, prefix, var_ctx, var_ctx_size, err, ptr);
			if (rc == FLT_OT_RET_ERROR) {
				retval = FLT_OT_RET_ERROR;

				break;
			}
			else if (rc > 0) {
				retval = n;

				break;
			}
		}
	}

	FLT_OT_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_ot_ctx_set_cb -
 *
 * ARGUMENTS
 *   smp      -
 *   idx      -
 *   scope    -
 *   prefix   -
 *   name     -
 *   name_len -
 *   err      -
 *   ptr      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_ctx_set_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OT_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct flt_ot_ctx *ctx = ptr;
	int                retval = 0;

	FLT_OT_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, scope, prefix, name, name_len, FLT_OT_DPTR_ARGS(err), ptr);

	if ((name_len == ctx->value_len) && (strncmp(name, ctx->value, name_len) == 0)) {
		FLT_OT_DBG(2, "ctx '%s' found\n", name);

		retval = 1;
	}

	FLT_OT_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_ot_ctx_set -
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
static int flt_ot_ctx_set(struct stream *s, const char *scope, const char *prefix, const char *name, uint opt, char **err)
{
	struct flt_ot_ctx ctx;
	struct sample     smp_ctx;
	char              var_name[BUFSIZ];
	bool              flag_alloc = 0;
	int               rc, var_name_len, retval = FLT_OT_RET_ERROR;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, name, opt, FLT_OT_DPTR_ARGS(err));

	/*
	 * The variable in which we will save the name of the OpenTracing
	 * context variable.
	 */
	var_name_len = flt_ot_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
	if (var_name_len == -1)
		FLT_OT_RETURN_INT(retval);

	/* Normalized name of the OpenTracing context variable. */
	ctx.value_len = flt_ot_var_name(name, NULL, NULL, 0, ctx.value, sizeof(ctx.value), err);
	if (ctx.value_len == -1)
		FLT_OT_RETURN_INT(retval);

	flt_ot_smp_init(s, &smp_ctx, opt, 0, NULL);

	retval = flt_ot_ctx_loop(&smp_ctx, scope, prefix, err, flt_ot_ctx_set_cb, &ctx);
	if (retval == 0) {
		rc = flt_ot_smp_add(&(smp_ctx.data), ctx.value, ctx.value_len, err);
		if (rc == FLT_OT_RET_ERROR)
			retval = FLT_OT_RET_ERROR;

		flag_alloc = (rc == 0);
	}

	if (retval == FLT_OT_RET_ERROR) {
		/* Do nothing. */
	}
	else if (retval > 0) {
		FLT_OT_DBG(2, "ctx '%s' data found", ctx.value);
	}
	else if (vars_set_by_name_ifexist(var_name, var_name_len, &smp_ctx) == 0) {
		FLT_OT_ERR("failed to set ctx '%s'", var_name);

		retval = FLT_OT_RET_ERROR;
	}
	else {
		FLT_OT_DBG(2, "ctx '%s' -> '%.*s' set", var_name, (int)b_data(&(smp_ctx.data.u.str)), b_orig(&(smp_ctx.data.u.str)));

		retval = b_data(&(smp_ctx.data.u.str));
	}

	if (flag_alloc)
		FLT_OT_FREE(b_orig(&(smp_ctx.data.u.str)));

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
		FLT_OT_DBG(2, "variable '%s' registered", var_name);

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

		if (strcmp(scope, FLT_OT_VARS_SCOPE) == 0)
			retval = flt_ot_ctx_set(s, scope, prefix, name, opt, err);
	}

	FLT_OT_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_ot_vars_unset_cb -
 *
 * ARGUMENTS
 *   smp      -
 *   idx      -
 *   scope    -
 *   prefix   -
 *   name     -
 *   name_len -
 *   err      -
 *   ptr      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_vars_unset_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OT_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct sample smp_ctx;
	char          var_ctx[BUFSIZ];
	int           var_ctx_len, retval = FLT_OT_RET_ERROR;

	FLT_OT_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, scope, prefix, name, name_len, FLT_OT_DPTR_ARGS(err), ptr);

	var_ctx_len = flt_ot_var_name(scope, prefix, name, 1, var_ctx, sizeof(var_ctx), err);
	if (var_ctx_len == -1) {
		FLT_OT_ERR("ctx '%s' invalid", name);

		FLT_OT_RETURN_INT(retval);
	}

	flt_ot_smp_init(smp->strm, &smp_ctx, smp->opt, 0, NULL);

	if (vars_unset_by_name_ifexist(var_ctx, var_ctx_len, &smp_ctx) == 0) {
		FLT_OT_ERR("ctx '%s' no variable found", var_ctx);
	} else {
		FLT_OT_DBG(2, "ctx '%s' unset", var_ctx);

		retval = 0;
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
	struct sample smp_ctx;
	char          var_name[BUFSIZ];
	int           var_name_len, retval;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, opt, FLT_OT_DPTR_ARGS(err));

	flt_ot_smp_init(s, &smp_ctx, opt, 0, NULL);

	retval = flt_ot_ctx_loop(&smp_ctx, scope, prefix, err, flt_ot_vars_unset_cb, NULL);
	if (retval != FLT_OT_RET_ERROR) {
		/*
		 * After all ctx variables have been unset, the variable used
		 * to store their names should also be unset.
		 */
		var_name_len = flt_ot_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
		if (var_name_len == -1)
			FLT_OT_RETURN_INT(FLT_OT_RET_ERROR);

		flt_ot_smp_init(s, &smp_ctx, opt, 0, NULL);

		if (vars_unset_by_name_ifexist(var_name, var_name_len, &smp_ctx) == 0) {
			FLT_OT_DBG(2, "variable '%s' not found", var_name);
		} else {
			FLT_OT_DBG(2, "variable '%s' unset", var_name);

			retval = 1;
		}
	}

	FLT_OT_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_ot_vars_get_cb -
 *
 * ARGUMENTS
 *   smp      -
 *   idx      -
 *   scope    -
 *   prefix   -
 *   name     -
 *   name_len -
 *   err      -
 *   ptr      -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static int flt_ot_vars_get_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OT_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct otc_text_map **map = ptr;
	struct sample         smp_ctx;
	char                  var_ctx[BUFSIZ], ot_var_name[BUFSIZ], ch;
	int                   var_ctx_len, ot_var_name_len, retval = FLT_OT_RET_ERROR;

	FLT_OT_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, scope, prefix, name, name_len, FLT_OT_DPTR_ARGS(err), ptr);

	var_ctx_len = flt_ot_var_name(scope, prefix, name, 1, var_ctx, sizeof(var_ctx), err);
	if (var_ctx_len == -1) {
		FLT_OT_ERR("ctx '%s' invalid", name);

		FLT_OT_RETURN_INT(retval);
	}

	flt_ot_smp_init(smp->strm, &smp_ctx, smp->opt, 0, NULL);

	if (vars_get_by_name(var_ctx, var_ctx_len, &smp_ctx, NULL) != 0) {
		FLT_OT_DBG(2, "'%s' -> '%.*s'", var_ctx, (int)b_data(&(smp_ctx.data.u.str)), b_orig(&(smp_ctx.data.u.str)));

		if (*map == NULL) {
			*map = otc_text_map_new(NULL, 8);
			if (*map == NULL) {
				FLT_OT_ERR("failed to create map data");

				FLT_OT_RETURN_INT(FLT_OT_RET_ERROR);
			}
		}

		/*
		 * Eh, because the use of some characters is not allowed
		 * in the variable name, the conversion of the replaced
		 * characters to the original is performed here.
		 */
		for (ot_var_name_len = 0; (ch = name[ot_var_name_len]) != '\0'; ot_var_name_len++)
			if (ot_var_name_len >= (FLT_OT_TABLESIZE(ot_var_name) - 1)) {
				FLT_OT_ERR("failed to reverse variable name, buffer too small");

				otc_text_map_destroy(map, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);

				break;
			} else {
				ot_var_name[ot_var_name_len] = (ch == FLT_OT_VAR_CHAR_DASH) ? '-' : ((ch == FLT_OT_VAR_CHAR_SPACE) ? ' ' : ch);
			}
		ot_var_name[ot_var_name_len] = '\0';

		if (*map == NULL) {
			retval = FLT_OT_RET_ERROR;
		}
		else if (otc_text_map_add(*map, ot_var_name, ot_var_name_len, b_orig(&(smp_ctx.data.u.str)), b_data(&(smp_ctx.data.u.str)), OTC_TEXT_MAP_DUP_KEY | OTC_TEXT_MAP_DUP_VALUE) == -1) {
			FLT_OT_ERR("failed to add map data");

			otc_text_map_destroy(map, OTC_TEXT_MAP_FREE_KEY | OTC_TEXT_MAP_FREE_VALUE);

			retval = FLT_OT_RET_ERROR;
		}
		else {
			retval = 0;
		}
	} else {
		FLT_OT_DBG(2, "ctx '%s' no variable found", var_ctx);
	}

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
	struct sample        smp_ctx;
	struct otc_text_map *retptr = NULL;

	FLT_OT_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, scope, prefix, opt, FLT_OT_DPTR_ARGS(err));

	flt_ot_smp_init(s, &smp_ctx, opt, 0, NULL);

	(void)flt_ot_ctx_loop(&smp_ctx, scope, prefix, err, flt_ot_vars_get_cb, &retptr);

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
