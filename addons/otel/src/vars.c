/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_vars_scope_dump - debug variable scope dump
 *
 * SYNOPSIS
 *   static void flt_otel_vars_scope_dump(struct vars *vars, const char *scope)
 *
 * ARGUMENTS
 *   vars  - HAProxy variable store to dump
 *   scope - scope label for log output
 *
 * DESCRIPTION
 *   Dumps the contents of all variables defined for a particular <scope>.
 *   Acquires a read lock on the variable store, iterates over all name root
 *   trees, and logs each variable's name hash and string value.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_vars_scope_dump(struct vars *vars, const char *scope)
{
	int i;

	if (vars == NULL)
		return;

	/* Lock the variable store for safe iteration. */
	vars_rdlock(vars);
	for (i = 0; i < VAR_NAME_ROOTS; i++) {
		struct ceb_node *node = cebu64_imm_first(&(vars->name_root[i]));

		for ( ; node != NULL; node = cebu64_imm_next(&(vars->name_root[i]), node)) {
			struct var *var = container_of(node, struct var, name_node);

			OTELC_DBG(NOTICE, "'%s.%016" PRIx64 "' -> '%.*s'", scope, var->name_hash, (int)b_data(&(var->data.u.str)), b_orig(&(var->data.u.str)));
		}
	}
	vars_rdunlock(vars);
}


/***
 * NAME
 *   flt_otel_vars_dump - debug all variables dump
 *
 * SYNOPSIS
 *   void flt_otel_vars_dump(struct stream *s)
 *
 * ARGUMENTS
 *   s - stream whose variables to dump
 *
 * DESCRIPTION
 *   Dumps all variables across all scopes (PROC, SESS, TXN, REQ/RES) by calling
 *   flt_otel_vars_scope_dump() for each scope's variable store.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_vars_dump(struct stream *s)
{
	OTELC_FUNC("%p", s);

	/*
	 * It would be nice if we could use the get_vars() function from HAProxy
	 * source here to get the value of the 'vars' pointer, but it is defined
	 * as 'static inline', so unfortunately none of this is possible.
	 */
	flt_otel_vars_scope_dump(&(proc_vars), "PROC");
	flt_otel_vars_scope_dump(&(s->sess->vars), "SESS");
	flt_otel_vars_scope_dump(&(s->vars_txn), "TXN");
	flt_otel_vars_scope_dump(&(s->vars_reqres), "REQ/RES");

	OTELC_RETURN();
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_normalize_name - variable name normalization
 *
 * SYNOPSIS
 *   static int flt_otel_normalize_name(char *var_name, size_t size, int *len, const char *name, bool flag_cpy, char **err)
 *
 * ARGUMENTS
 *   var_name - output buffer for the normalized name
 *   size     - output buffer size
 *   len      - pointer to the current position in the output buffer
 *   name     - source name to normalize
 *   flag_cpy - whether to copy name without normalization
 *   err      - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Normalizes a variable name component into the output buffer.  Adds a
 *   dot separator between components when needed.  When <flag_cpy> is set,
 *   the name is copied verbatim; otherwise, dashes are replaced with
 *   FLT_OTEL_VAR_CHAR_DASH, spaces with FLT_OTEL_VAR_CHAR_SPACE, and uppercase
 *   letters are converted to lowercase.
 *
 * RETURN VALUE
 *   Returns the number of characters written, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_normalize_name(char *var_name, size_t size, int *len, const char *name, bool flag_cpy, char **err)
{
	int retval = 0;

	OTELC_FUNC("%p, %zu, %p, \"%s\", %hhu, %p:%p", var_name, size, len, OTELC_STR_ARG(name), flag_cpy, OTELC_DPTR_ARGS(err));

	if (!OTELC_STR_IS_VALID(name))
		OTELC_RETURN_INT(retval);

	/*
	 * In case the name of the variable consists of several elements,
	 * the character '.' is added between them.
	 */
	if ((*len == 0) || (var_name[*len - 1] == '.'))
		/* Do nothing. */;
	else if (*len < (size - 1))
		var_name[(*len)++] = '.';
	else {
		FLT_OTEL_ERR("failed to normalize variable name, buffer too small");

		retval = FLT_OTEL_RET_ERROR;
	}

	if (retval == FLT_OTEL_RET_ERROR) {
		/* Do nothing. */
	}
	else if (flag_cpy) {
		/* Copy variable name without modification. */
		retval = strlen(name);
		if ((*len + retval + 1) > size) {
			FLT_OTEL_ERR("failed to normalize variable name, buffer too small");

			retval = FLT_OTEL_RET_ERROR;
		} else {
			(void)memcpy(var_name + *len, name, retval + 1);

			*len += retval;
		}
	} else {
		/*
		 * HAProxy does not allow the use of variable names containing
		 * '-' or ' '.  This of course applies to HTTP header names as
		 * well.  Also, here the capital letters are converted to
		 * lowercase.
		 */
		while (retval != FLT_OTEL_RET_ERROR)
			if (*len >= (size - 1)) {
				FLT_OTEL_ERR("failed to normalize variable name, buffer too small");

				retval = FLT_OTEL_RET_ERROR;
			} else {
				uint8_t ch = name[retval];

				if (ch == '\0')
					break;
				else if (ch == '-')
					ch = FLT_OTEL_VAR_CHAR_DASH;
				else if (ch == ' ')
					ch = FLT_OTEL_VAR_CHAR_SPACE;
				else if (isupper(ch))
					ch = ist_lc[ch];

				var_name[(*len)++] = ch;
				retval++;
			}

		var_name[*len] = '\0';
	}

	OTELC_DBG(DEBUG, "var_name: \"%s\" %d/%d", OTELC_STR_ARG(var_name), retval, *len);

	if (retval == FLT_OTEL_RET_ERROR)
		*len = retval;

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_denormalize_name - reverse variable name normalization
 *
 * SYNOPSIS
 *   static int flt_otel_denormalize_name(const char *var_name, char *name, size_t size, char **err)
 *
 * ARGUMENTS
 *   var_name - normalized variable name
 *   name     - output buffer for the denormalized name
 *   size     - output buffer size
 *   err      - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Reverses the normalization applied by flt_otel_normalize_name().  Restores
 *   dashes from FLT_OTEL_VAR_CHAR_DASH and spaces from FLT_OTEL_VAR_CHAR_SPACE.
 *
 * RETURN VALUE
 *   Returns the length of the denormalized name, or FLT_OTEL_RET_ERROR if the
 *   output buffer is too small.
 */
static int flt_otel_denormalize_name(const char *var_name, char *name, size_t size, char **err)
{
	int len;

	/* Reverse character substitutions applied during normalization. */
	for (len = 0; var_name[len] != '\0'; len++) {
		if (len >= (size - 1)) {
			FLT_OTEL_ERR("failed to reverse variable name, buffer too small");

			return FLT_OTEL_RET_ERROR;
		}

		if (var_name[len] == FLT_OTEL_VAR_CHAR_DASH)
			name[len] = '-';
		else if (var_name[len] == FLT_OTEL_VAR_CHAR_SPACE)
			name[len] = ' ';
		else
			name[len] = var_name[len];
	}
	name[len] = '\0';

	return len;
}


/***
 * NAME
 *   flt_otel_var_name - full variable name construction
 *
 * SYNOPSIS
 *   static int flt_otel_var_name(const char *scope, const char *prefix, const char *name, bool flag_cpy, char *var_name, size_t size, char **err)
 *
 * ARGUMENTS
 *   scope    - variable scope component
 *   prefix   - variable prefix component
 *   name     - variable name component
 *   flag_cpy - whether to copy name without normalization
 *   var_name - output buffer for the constructed name
 *   size     - output buffer size
 *   err      - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Constructs a full variable name from <scope>, <prefix>, and <name>
 *   components, separated by dots.  Each component is normalized via
 *   flt_otel_normalize_name().  NULL components are skipped.
 *
 * RETURN VALUE
 *   Returns the total name length, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_var_name(const char *scope, const char *prefix, const char *name, bool flag_cpy, char *var_name, size_t size, char **err)
{
	int retval = 0;

	OTELC_FUNC("\"%s\", \"%s\", \"%s\", %hhu, %p, %zu, %p:%p", OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), flag_cpy, var_name, size, OTELC_DPTR_ARGS(err));

	if (flt_otel_normalize_name(var_name, size, &retval, scope, 0, err) >= 0)
		if (flt_otel_normalize_name(var_name, size, &retval, prefix, 0, err) >= 0)
			(void)flt_otel_normalize_name(var_name, size, &retval, name, flag_cpy, err);

	if (retval == FLT_OTEL_RET_ERROR)
		FLT_OTEL_ERR("failed to construct variable name '%s.%s.%s'", scope, prefix, name);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_smp_init - sample structure initialization
 *
 * SYNOPSIS
 *   static inline void flt_otel_smp_init(struct stream *s, struct sample *smp, uint opt, int type, const char *data)
 *
 * ARGUMENTS
 *   s    - current stream
 *   smp  - sample structure to initialize
 *   opt  - sample option flags
 *   type - sample data type
 *   data - string data to store (or NULL)
 *
 * DESCRIPTION
 *   Initializes the <smp> structure and sets stream ownership via
 *   smp_set_owner().  If the <data> argument is non-NULL, the sample_data
 *   member is also initialized with the given <type> and string content.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static inline void flt_otel_smp_init(struct stream *s, struct sample *smp, uint opt, int type, const char *data)
{
	(void)memset(smp, 0, sizeof(*smp));
	(void)smp_set_owner(smp, s->be, s->sess, s, opt | SMP_OPT_FINAL);

	if (data != NULL) {
		smp->data.type = type;

		chunk_initstr(&(smp->data.u.str), data);
	}
}


#ifndef USE_OTEL_VARS_NAME

/***
 * NAME
 *   flt_otel_smp_add - context variable name registration
 *
 * SYNOPSIS
 *   static int flt_otel_smp_add(struct sample_data *data, const char *name, size_t len, char **err)
 *
 * ARGUMENTS
 *   data - binary sample data buffer
 *   name - context variable name to append
 *   len  - length of the variable name
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Appends a context variable name to the binary sample data buffer used for
 *   tracking registered context variables.  If the buffer is not yet allocated,
 *   it is initialized with global.tune.bufsize bytes.  The name is stored as a
 *   length-prefixed entry (FLT_OTEL_VAR_CTX_SIZE byte followed by the name
 *   data).  Validates that the name length fits in the size field and that the
 *   buffer has sufficient room.
 *
 * RETURN VALUE
 *   Returns the buffer offset before appending, or FLT_OTEL_RET_ERROR on
 *   failure.
 */
static int flt_otel_smp_add(struct sample_data *data, const char *name, size_t len, char **err)
{
	bool flag_alloc = 0;
	int  retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, \"%.*s\", %zu, %p:%p", data, (int)len, name, len, OTELC_DPTR_ARGS(err));

	FLT_OTEL_DBG_BUF(INFO, &(data->u.str));

	/* Lazily allocate the sample buffer on first use. */
	if (b_orig(&(data->u.str)) == NULL) {
		data->type = SMP_T_BIN;
		chunk_init(&(data->u.str), OTELC_MALLOC(global.tune.bufsize), global.tune.bufsize);

		flag_alloc = (b_orig(&(data->u.str)) != NULL);
	}

	/* Verify the buffer allocation succeeded. */
	if (b_orig(&(data->u.str)) == NULL) {
		FLT_OTEL_ERR("failed to add ctx '%.*s', not enough memory", (int)len, name);
	}
	else if (len > ((UINT64_C(1) << ((sizeof(FLT_OTEL_VAR_CTX_SIZE) << 3) - 1)) - 1)) {
		FLT_OTEL_ERR("failed to add ctx '%.*s', name too long", (int)len, name);
	}
	else if ((len + sizeof(FLT_OTEL_VAR_CTX_SIZE)) > b_room(&(data->u.str))) {
		FLT_OTEL_ERR("failed to add ctx '%.*s', too many names", (int)len, name);
	}
	else {
		retval = b_data(&(data->u.str));

		b_putchr(&(data->u.str), len);
		(void)__b_putblk(&(data->u.str), name, len);

		FLT_OTEL_DBG_BUF(INFO, &(data->u.str));
	}

	if ((retval == FLT_OTEL_RET_ERROR) && flag_alloc)
		OTELC_SFREE(b_orig(&(data->u.str)));

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ctx_loop - context variable name iterator
 *
 * SYNOPSIS
 *   static int flt_otel_ctx_loop(struct sample *smp, const char *scope, const char *prefix, char **err, flt_otel_ctx_loop_cb func, void *ptr)
 *
 * ARGUMENTS
 *   smp    - sample used to retrieve the context tracking variable
 *   scope  - variable scope
 *   prefix - variable prefix
 *   err    - indirect pointer to error message string
 *   func   - callback function invoked for each context variable
 *   ptr    - opaque data passed to the callback
 *
 * DESCRIPTION
 *   Iterates over all context variable names stored in the binary tracking
 *   buffer.  Retrieves the tracking variable by constructing its name from
 *   <scope> and <prefix>.  Each stored entry (length-prefixed name) is
 *   extracted and passed to the <func> callback.  Iteration stops if the
 *   callback returns a positive value (match found) or FLT_OTEL_RET_ERROR.
 *
 * RETURN VALUE
 *   Returns the match position (positive), 0 if no match,
 *   or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_ctx_loop(struct sample *smp, const char *scope, const char *prefix, char **err, flt_otel_ctx_loop_cb func, void *ptr)
{
	FLT_OTEL_VAR_CTX_SIZE var_ctx_size;
	char                  var_name[BUFSIZ], var_ctx[BUFSIZ];
	int                   i, var_name_len, var_ctx_len, rc, n = 1, retval = 0;

	OTELC_FUNC("%p, \"%s\", \"%s\", %p:%p, %p, %p", smp, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_DPTR_ARGS(err), func, ptr);

	/*
	 * The variable in which we will save the name of the OpenTelemetry
	 * context variable.
	 */
	var_name_len = flt_otel_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
	if (var_name_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	/*
	 * Here we will try to find all the previously recorded variables from
	 * the currently set OpenTelemetry context.  If we find the required
	 * variable and it is marked as deleted, we will mark it as active.
	 * If we do not find it, then it is added to the end of the previously
	 * saved names.
	 */
	if (vars_get_by_name(var_name, var_name_len, smp, NULL) == 0) {
		OTELC_DBG(NOTICE, "ctx '%s' no variable found", var_name);
	}
	else if (smp->data.type != SMP_T_BIN) {
		FLT_OTEL_ERR("ctx '%s' invalid data type %d", var_name, smp->data.type);

		retval = FLT_OTEL_RET_ERROR;
	}
	else {
		FLT_OTEL_DBG_BUF(INFO, &(smp->data.u.str));

		for (i = 0; i < b_data(&(smp->data.u.str)); i += sizeof(var_ctx_size) + var_ctx_len, n++) {
			var_ctx_size = *((typeof(var_ctx_size) *)(b_orig(&(smp->data.u.str)) + i));
			var_ctx_len  = abs(var_ctx_size);

			if ((i + sizeof(var_ctx_size) + var_ctx_len) > b_data(&(smp->data.u.str))) {
				FLT_OTEL_ERR("ctx '%s' invalid data size", var_name);

				retval = FLT_OTEL_RET_ERROR;

				break;
			}

			(void)memcpy(var_ctx, b_orig(&(smp->data.u.str)) + i + sizeof(var_ctx_size), var_ctx_len);
			var_ctx[var_ctx_len] = '\0';

			rc = func(smp, i, scope, prefix, var_ctx, var_ctx_size, err, ptr);
			if (rc == FLT_OTEL_RET_ERROR) {
				retval = FLT_OTEL_RET_ERROR;

				break;
			}
			else if (rc > 0) {
				retval = n;

				break;
			}
		}
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ctx_set_cb - context variable existence check callback
 *
 * SYNOPSIS
 *   static int flt_otel_ctx_set_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
 *
 * ARGUMENTS
 *   smp      - current sample (unused)
 *   idx      - buffer offset (unused)
 *   scope    - variable scope (unused)
 *   prefix   - variable prefix (unused)
 *   name     - context variable name to check
 *   name_len - length of the name
 *   err      - unused
 *   ptr      - pointer to flt_otel_ctx structure with the search target
 *
 * DESCRIPTION
 *   Callback for flt_otel_ctx_loop() that checks whether a context variable
 *   <name> matches the search target stored in the flt_otel_ctx structure.
 *
 * RETURN VALUE
 *   Returns 1 if the <name> matches, or 0 otherwise.
 */
static int flt_otel_ctx_set_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct flt_otel_ctx *ctx = ptr;
	int                  retval = 0;

	OTELC_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), name_len, OTELC_DPTR_ARGS(err), ptr);

	if ((name_len == ctx->value_len) && (strncmp(name, ctx->value, name_len) == 0)) {
		OTELC_DBG(NOTICE, "ctx '%s' found", name);

		retval = 1;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ctx_set - context variable tracking registration
 *
 * SYNOPSIS
 *   static int flt_otel_ctx_set(struct stream *s, const char *scope, const char *prefix, const char *name, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   name   - context variable name to register
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Registers a context variable name in the binary tracking buffer if it is
 *   not already present.  Constructs the tracking variable name from <scope>
 *   and <prefix>, then uses flt_otel_ctx_loop() with flt_otel_ctx_set_cb() to
 *   check for duplicates.  If not found, the normalized name is appended to the
 *   tracking buffer via flt_otel_smp_add() and the updated buffer is stored
 *   back into the HAProxy variable.
 *
 * RETURN VALUE
 *   Returns the buffer data size on success, a positive value if already
 *   registered, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_ctx_set(struct stream *s, const char *scope, const char *prefix, const char *name, uint opt, char **err)
{
	struct flt_otel_ctx ctx;
	struct sample       smp_ctx;
	char                var_name[BUFSIZ];
	bool                flag_alloc = 0;
	int                 rc, var_name_len, retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, \"%s\", \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), opt, OTELC_DPTR_ARGS(err));

	/*
	 * The variable in which we will save the name of the OpenTelemetry
	 * context variable.
	 */
	var_name_len = flt_otel_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
	if (var_name_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(retval);

	/* Normalized name of the OpenTelemetry context variable. */
	ctx.value_len = flt_otel_var_name(name, NULL, NULL, 0, ctx.value, sizeof(ctx.value), err);
	if (ctx.value_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(retval);

	flt_otel_smp_init(s, &smp_ctx, opt, 0, NULL);

	/* Loop through existing context variables and apply set operations. */
	retval = flt_otel_ctx_loop(&smp_ctx, scope, prefix, err, flt_otel_ctx_set_cb, &ctx);
	if (retval == 0) {
		rc = flt_otel_smp_add(&(smp_ctx.data), ctx.value, ctx.value_len, err);
		if (rc == FLT_OTEL_RET_ERROR)
			retval = FLT_OTEL_RET_ERROR;

		flag_alloc = (rc == 0);
	}

	/* Persist the context data as a HAProxy variable. */
	if (retval == FLT_OTEL_RET_ERROR) {
		/* Do nothing. */
	}
	else if (retval > 0) {
		OTELC_DBG(NOTICE, "ctx '%s' data found", ctx.value);
	}
	else if (vars_set_by_name_ifexist(var_name, var_name_len, &smp_ctx) == 0) {
		FLT_OTEL_ERR("failed to set ctx '%s'", var_name);

		retval = FLT_OTEL_RET_ERROR;
	}
	else {
		OTELC_DBG(NOTICE, "ctx '%s' -> '%.*s' set", var_name, (int)b_data(&(smp_ctx.data.u.str)), b_orig(&(smp_ctx.data.u.str)));

		retval = b_data(&(smp_ctx.data.u.str));
	}

	if (flag_alloc)
		OTELC_SFREE(b_orig(&(smp_ctx.data.u.str)));

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_vars_unset_cb - context variable unset callback
 *
 * SYNOPSIS
 *   static int flt_otel_vars_unset_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
 *
 * ARGUMENTS
 *   smp      - current sample with stream context
 *   idx      - buffer offset (unused)
 *   scope    - variable scope
 *   prefix   - variable prefix
 *   name     - context variable name to unset
 *   name_len - length of the name (unused)
 *   err      - indirect pointer to error message string
 *   ptr      - unused
 *
 * DESCRIPTION
 *   Callback for flt_otel_ctx_loop() that unsets a single context variable.
 *   Constructs the full variable name from <scope>, <prefix>, and <name>, then
 *   calls vars_unset_by_name_ifexist() to remove it.
 *
 * RETURN VALUE
 *   Returns 0 on success, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_vars_unset_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct sample smp_ctx;
	char          var_ctx[BUFSIZ];
	int           var_ctx_len, retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), name_len, OTELC_DPTR_ARGS(err), ptr);

	var_ctx_len = flt_otel_var_name(scope, prefix, name, 1, var_ctx, sizeof(var_ctx), err);
	if (var_ctx_len == FLT_OTEL_RET_ERROR) {
		FLT_OTEL_ERR("ctx '%s' invalid", name);

		OTELC_RETURN_INT(retval);
	}

	flt_otel_smp_init(smp->strm, &smp_ctx, smp->opt, 0, NULL);

	if (vars_unset_by_name_ifexist(var_ctx, var_ctx_len, &smp_ctx) == 0) {
		FLT_OTEL_ERR("ctx '%s' no variable found", var_ctx);
	} else {
		OTELC_DBG(NOTICE, "ctx '%s' unset", var_ctx);

		retval = 0;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_vars_unset - context variables bulk unset
 *
 * SYNOPSIS
 *   int flt_otel_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Unsets all context variables for a given <prefix> by iterating the tracking
 *   buffer via flt_otel_ctx_loop() with flt_otel_vars_unset_cb().  After all
 *   individual context variables are removed, the tracking variable itself
 *   (which stores the list of names) is also unset.
 *
 * RETURN VALUE
 *   Returns 1 on success, 0 if no tracking variable exists,
 *   or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct sample smp_ctx;
	char          var_name[BUFSIZ];
	int           var_name_len, retval;

	OTELC_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), opt, OTELC_DPTR_ARGS(err));

	flt_otel_smp_init(s, &smp_ctx, opt, 0, NULL);

	retval = flt_otel_ctx_loop(&smp_ctx, scope, prefix, err, flt_otel_vars_unset_cb, NULL);
	if (retval != FLT_OTEL_RET_ERROR) {
		/*
		 * After all ctx variables have been unset, the variable used
		 * to store their names should also be unset.
		 */
		var_name_len = flt_otel_var_name(scope, prefix, NULL, 0, var_name, sizeof(var_name), err);
		if (var_name_len == FLT_OTEL_RET_ERROR)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

		flt_otel_smp_init(s, &smp_ctx, opt, 0, NULL);

		if (vars_unset_by_name_ifexist(var_name, var_name_len, &smp_ctx) == 0) {
			OTELC_DBG(NOTICE, "variable '%s' not found", var_name);
		} else {
			OTELC_DBG(NOTICE, "variable '%s' unset", var_name);

			retval = 1;
		}
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_vars_get_cb - context variable value reader callback
 *
 * SYNOPSIS
 *   static int flt_otel_vars_get_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
 *
 * ARGUMENTS
 *   smp      - current sample with stream context
 *   idx      - buffer offset (unused)
 *   scope    - variable scope
 *   prefix   - variable prefix
 *   name     - normalized context variable name
 *   name_len - length of the name (unused)
 *   err      - indirect pointer to error message string
 *   ptr      - pointer to the output text map pointer
 *
 * DESCRIPTION
 *   Callback for flt_otel_ctx_loop() that reads a single context variable value
 *   and adds it to a text map.  Constructs the full variable name, reads its
 *   value via vars_get_by_name(), reverses the <name> normalization (restoring
 *   dashes and spaces), and stores the key-value pair in the text map.  The
 *   text map is lazily allocated on first use.
 *
 * RETURN VALUE
 *   Returns 0 on success, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_vars_get_cb(struct sample *smp, size_t idx, const char *scope, const char *prefix, const char *name, FLT_OTEL_VAR_CTX_SIZE name_len, char **err, void *ptr)
{
	struct otelc_text_map **map = ptr;
	struct sample           smp_ctx;
	char                    var_ctx[BUFSIZ], otel_var_name[BUFSIZ];
	int                     var_ctx_len, retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %zu, \"%s\", \"%s\", \"%s\", %hhd, %p:%p, %p", smp, idx, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), name_len, OTELC_DPTR_ARGS(err), ptr);

	/* Build the HAProxy variable name for this context key. */
	var_ctx_len = flt_otel_var_name(scope, prefix, name, 1, var_ctx, sizeof(var_ctx), err);
	if (var_ctx_len == FLT_OTEL_RET_ERROR) {
		FLT_OTEL_ERR("ctx '%s' invalid", name);

		OTELC_RETURN_INT(retval);
	}

	flt_otel_smp_init(smp->strm, &smp_ctx, smp->opt, 0, NULL);

	/* Retrieve the context variable and build a text map entry. */
	if (vars_get_by_name(var_ctx, var_ctx_len, &smp_ctx, NULL) != 0) {
		OTELC_DBG(NOTICE, "'%s' -> '%.*s'", var_ctx, (int)b_data(&(smp_ctx.data.u.str)), b_orig(&(smp_ctx.data.u.str)));

		if (*map == NULL) {
			*map = OTELC_TEXT_MAP_NEW(NULL, 8);
			if (*map == NULL) {
				FLT_OTEL_ERR("failed to create map data");

				OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
			}
		}

		/*
		 * Eh, because the use of some characters is not allowed in the
		 * variable name, the conversion of the replaced characters to
		 * the original is performed here.
		 */
		retval = flt_otel_denormalize_name(name, otel_var_name, OTELC_TABLESIZE_1(otel_var_name), err);
		if (retval >= 0)
			retval = OTELC_TEXT_MAP_ADD(*map, otel_var_name, retval, b_orig(&(smp_ctx.data.u.str)), b_data(&(smp_ctx.data.u.str)), OTELC_TEXT_MAP_AUTO);
		if (retval == FLT_OTEL_RET_ERROR) {
			FLT_OTEL_ERR("failed to add map data");

			otelc_text_map_destroy(map);
		} else {
			retval = 0;
		}
	} else {
		OTELC_DBG(NOTICE, "ctx '%s' no variable found", var_ctx);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_vars_get - context variables to text map extraction
 *
 * SYNOPSIS
 *   struct otelc_text_map *flt_otel_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Reads all context variables for a given <prefix> into a text map.  Iterates
 *   the tracking buffer via flt_otel_ctx_loop() with flt_otel_vars_get_cb().
 *   If the resulting text map is empty, it is destroyed and NULL is returned.
 *   This function is used by the "extract" keyword with variable storage.
 *
 * RETURN VALUE
 *   Returns a pointer to the populated text map, or NULL if no variables are
 *   found.
 */
struct otelc_text_map *flt_otel_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct sample          smp_ctx;
	struct otelc_text_map *retptr = NULL;

	OTELC_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), opt, OTELC_DPTR_ARGS(err));

	flt_otel_smp_init(s, &smp_ctx, opt, 0, NULL);

	(void)flt_otel_ctx_loop(&smp_ctx, scope, prefix, err, flt_otel_vars_get_cb, &retptr);

	OTELC_TEXT_MAP_DUMP(retptr, "extracted variables");

	if ((retptr != NULL) && (retptr->count == 0)) {
		OTELC_DBG(NOTICE, "WARNING: no variables found");

		otelc_text_map_destroy(&retptr);
	}

	OTELC_RETURN_PTR(retptr);
}

#else

/***
 * NAME
 *   flt_otel_vars_get_scope - resolve scope string to variable store
 *
 * SYNOPSIS
 *   static struct vars *flt_otel_vars_get_scope(struct stream *s, const char *scope)
 *
 * ARGUMENTS
 *   s     - current stream
 *   scope - variable scope string ("proc", "sess", "txn", "req", "res")
 *
 * DESCRIPTION
 *   Resolves a scope name string to the corresponding HAProxy variable
 *   store for the given <stream>.
 *
 * RETURN VALUE
 *   Returns a pointer to the variable store, or NULL if the <scope>
 *   is unknown.
 */
static struct vars *flt_otel_vars_get_scope(struct stream *s, const char *scope)
{
	if (strcmp(scope, "txn") == 0)
		return &(s->vars_txn);
	else if (strcmp(scope, "req") == 0)
		return &(s->vars_reqres);
	else if (strcmp(scope, "res") == 0)
		return &(s->vars_reqres);
	else if (strcmp(scope, "sess") == 0)
		return &(s->sess->vars);
	else if (strcmp(scope, "proc") == 0)
		return &proc_vars;

	return NULL;
}


/***
 * NAME
 *   flt_otel_vars_unset - context variables bulk unset via prefix scan
 *
 * SYNOPSIS
 *   int flt_otel_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Unsets all context variables whose name starts with the normalized
 *   <prefix> followed by a dot.  Walks the CEB tree of the variable
 *   store for the given <scope> and removes each matching variable.
 *
 * RETURN VALUE
 *   Returns the number of variables removed, 0 if none found,
 *   or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct vars    *vars;
	char            norm_prefix[BUFSIZ];
	unsigned int    size = 0;
	int             prefix_len, retval = 0, i;

	OTELC_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), opt, OTELC_DPTR_ARGS(err));

	prefix_len = flt_otel_var_name(prefix, NULL, NULL, 0, norm_prefix, sizeof(norm_prefix), err);
	if (prefix_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	vars = flt_otel_vars_get_scope(s, scope);
	if (vars == NULL)
		OTELC_RETURN_INT(0);

	/* Lock and iterate all variables, clearing those matching the prefix. */
	vars_wrlock(vars);
	for (i = 0; i < VAR_NAME_ROOTS; i++) {
		struct ceb_node *node = cebu64_imm_first(&(vars->name_root[i]));

		while (node != NULL) {
			struct var      *var = container_of(node, struct var, name_node);
			struct ceb_node *next = cebu64_imm_next(&(vars->name_root[i]), node);

			if ((var->name != NULL) &&
			    (strncmp(var->name, norm_prefix, prefix_len) == 0) &&
			    (var->name[prefix_len] == '.')) {
				OTELC_DBG(NOTICE, "prefix unset '%s'", var->name);

				size += var_clear(vars, var, 1);
				retval++;
			}

			node = next;
		}
	}
	vars_wrunlock(vars);

	if (size > 0)
		var_accounting_diff(vars, s->sess, s, -(int)size);

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_vars_get - context variables to text map via prefix scan
 *
 * SYNOPSIS
 *   struct otelc_text_map *flt_otel_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Reads all context variables whose name starts with the normalized
 *   <prefix> followed by a dot.  Walks the CEB tree of the variable
 *   store for the given <scope>, denormalizes each matching variable
 *   name, and adds the key-value pair to the returned text map.
 *
 * RETURN VALUE
 *   Returns a pointer to the populated text map, or NULL if no
 *   variables are found.
 */
struct otelc_text_map *flt_otel_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err)
{
	struct vars           *vars;
	struct otelc_text_map *retptr = NULL;
	char                   norm_prefix[BUFSIZ], otel_name[BUFSIZ];
	int                    prefix_len, i;

	OTELC_FUNC("%p, \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), opt, OTELC_DPTR_ARGS(err));

	prefix_len = flt_otel_var_name(prefix, NULL, NULL, 0, norm_prefix, sizeof(norm_prefix), err);
	if (prefix_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_PTR(NULL);

	vars = flt_otel_vars_get_scope(s, scope);
	if (vars == NULL)
		OTELC_RETURN_PTR(NULL);

	/* Read-lock and collect all variables matching the prefix into a text map. */
	vars_rdlock(vars);
	for (i = 0; i < VAR_NAME_ROOTS; i++) {
		struct ceb_node *node = cebu64_imm_first(&(vars->name_root[i]));

		for ( ; node != NULL; node = cebu64_imm_next(&(vars->name_root[i]), node)) {
			struct var *var = container_of(node, struct var, name_node);
			const char *key;
			int         otel_name_len;

			if ((var->name == NULL) ||
			    (strncmp(var->name, norm_prefix, prefix_len) != 0) ||
			    (var->name[prefix_len] != '.'))
				continue;

			/* Skip the "prefix." part to get the key name. */
			key = var->name + prefix_len + 1;

			otel_name_len = flt_otel_denormalize_name(key, otel_name, sizeof(otel_name), err);
			if (otel_name_len == FLT_OTEL_RET_ERROR) {
				FLT_OTEL_ERR("failed to reverse variable name, buffer too small");

				break;
			}

			if ((var->data.type != SMP_T_STR) && (var->data.type != SMP_T_BIN)) {
				OTELC_DBG(NOTICE, "skipping '%s', unsupported type %d", var->name, var->data.type);

				continue;
			}

			OTELC_DBG(NOTICE, "'%s' -> '%.*s'", var->name, (int)b_data(&(var->data.u.str)), b_orig(&(var->data.u.str)));

			if (retptr == NULL) {
				retptr = OTELC_TEXT_MAP_NEW(NULL, 8);
				if (retptr == NULL) {
					FLT_OTEL_ERR("failed to create map data");

					break;
				}
			}

			if (OTELC_TEXT_MAP_ADD(retptr, otel_name, otel_name_len, b_orig(&(var->data.u.str)), b_data(&(var->data.u.str)), OTELC_TEXT_MAP_AUTO) == -1) {
				FLT_OTEL_ERR("failed to add map data");

				otelc_text_map_destroy(&retptr);

				break;
			}
		}
	}
	vars_rdunlock(vars);

	OTELC_TEXT_MAP_DUMP(retptr, "extracted variables");

	if ((retptr != NULL) && (retptr->count == 0)) {
		OTELC_DBG(NOTICE, "WARNING: no variables found");

		otelc_text_map_destroy(&retptr);
	}

	OTELC_RETURN_PTR(retptr);
}

#endif /* USE_OTEL_VARS_NAME */


/***
 * NAME
 *   flt_otel_var_register - HAProxy variable registration
 *
 * SYNOPSIS
 *   int flt_otel_var_register(const char *scope, const char *prefix, const char *name, char **err)
 *
 * ARGUMENTS
 *   scope  - variable scope
 *   prefix - variable prefix
 *   name   - variable name
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Registers a HAProxy variable by constructing its full name from <scope>,
 *   <prefix>, and <name>, then calling vars_check_arg() to make it available
 *   at runtime.
 *
 * RETURN VALUE
 *   Returns the variable name length on success, or FLT_OTEL_RET_ERROR on
 *   failure.
 */
int flt_otel_var_register(const char *scope, const char *prefix, const char *name, char **err)
{
	struct arg arg;
	char       var_name[BUFSIZ];
	int        retval = FLT_OTEL_RET_ERROR, var_name_len;

	OTELC_FUNC("\"%s\", \"%s\", \"%s\", %p:%p", OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), OTELC_DPTR_ARGS(err));

	var_name_len = flt_otel_var_name(scope, prefix, name, 0, var_name, sizeof(var_name), err);
	if (var_name_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(retval);

	/* Set <size> to 0 to not release var_name memory in vars_check_arg(). */
	(void)memset(&arg, 0, sizeof(arg));
	arg.type          = ARGT_STR;
	arg.data.str.area = var_name;
	arg.data.str.data = var_name_len;

	if (vars_check_arg(&arg, err) == 0) {
		FLT_OTEL_ERR_APPEND("failed to register variable '%s': %s", var_name, *err);
	} else {
		OTELC_DBG(NOTICE, "variable '%s' registered", var_name);

		retval = var_name_len;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_var_set - HAProxy variable value setter
 *
 * SYNOPSIS
 *   int flt_otel_var_set(struct stream *s, const char *scope, const char *prefix, const char *name, const char *value, uint opt, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   scope  - variable scope
 *   prefix - variable prefix
 *   name   - variable name
 *   value  - string value to set
 *   opt    - sample option flags
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Sets a HAProxy variable to the given string <value>.  The full variable
 *   name is constructed from <scope>, <prefix>, and <name>.  If the variable's
 *   scope matches FLT_OTEL_VARS_SCOPE, the name is also registered in the
 *   context tracking buffer via flt_otel_ctx_set().
 *
 * RETURN VALUE
 *   Returns the variable name length on success, the context tracking result
 *   for context-scope variables, or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_var_set(struct stream *s, const char *scope, const char *prefix, const char *name, const char *value, uint opt, char **err)
{
	struct sample smp;
	char          var_name[BUFSIZ];
	int           retval = FLT_OTEL_RET_ERROR, var_name_len;

	OTELC_FUNC("%p, \"%s\", \"%s\", \"%s\", \"%s\", %u, %p:%p", s, OTELC_STR_ARG(scope), OTELC_STR_ARG(prefix), OTELC_STR_ARG(name), OTELC_STR_ARG(value), opt, OTELC_DPTR_ARGS(err));

	var_name_len = flt_otel_var_name(scope, prefix, name, 0, var_name, sizeof(var_name), err);
	if (var_name_len == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(retval);

	flt_otel_smp_init(s, &smp, opt, SMP_T_STR, value);

	/* Set the variable if it already exists. */
	if (vars_set_by_name_ifexist(var_name, var_name_len, &smp) == 0) {
		FLT_OTEL_ERR("failed to set variable '%s'", var_name);
	} else {
		OTELC_DBG(NOTICE, "variable '%s' set", var_name);

		retval = var_name_len;

#ifndef USE_OTEL_VARS_NAME
		if (strcmp(scope, FLT_OTEL_VARS_SCOPE) == 0)
			retval = flt_otel_ctx_set(s, scope, prefix, name, opt, err);
#endif
	}

	OTELC_RETURN_INT(retval);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
