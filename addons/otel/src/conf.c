/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/***
 * NAME
 *   flt_otel_conf_hdr_init - conf_hdr structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_hdr *flt_otel_conf_hdr_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_hdr structure.  The <id> string is
 *   duplicated and stored as the header identifier.  If <head> is non-NULL,
 *   the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(hdr, id, )


/***
 * NAME
 *   flt_otel_conf_hdr_free - conf_hdr structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_hdr_free(struct flt_otel_conf_hdr **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_hdr structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(hdr, id,
	FLT_OTEL_DBG_CONF_HDR("- conf_hdr free ", *ptr, id);
)


/***
 * NAME
 *   flt_otel_conf_str_init - conf_str structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_str *flt_otel_conf_str_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_str structure.  The <id> string is
 *   duplicated and stored as the string value.  If <head> is non-NULL, the
 *   structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(str, str, )


/***
 * NAME
 *   flt_otel_conf_str_free - conf_str structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_str_free(struct flt_otel_conf_str **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_str structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(str, str,
	FLT_OTEL_DBG_CONF_HDR("- conf_str free ", *ptr, str);
)


/***
 * NAME
 *   flt_otel_conf_link_init - conf_link structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_link *flt_otel_conf_link_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_link structure for a span link
 *   reference.  The <id> string is duplicated and stored as the linked
 *   span name.  If <head> is non-NULL, the structure is appended to
 *   the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(link, span, )


/***
 * NAME
 *   flt_otel_conf_link_free - conf_link structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_link_free(struct flt_otel_conf_link **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_link structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(link, span,
	FLT_OTEL_DBG_CONF_HDR("- conf_link free ", *ptr, span);
)


/***
 * NAME
 *   flt_otel_conf_ph_init - conf_ph placeholder structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_ph *flt_otel_conf_ph_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_ph (placeholder) structure.  The <id>
 *   string is duplicated and stored as the placeholder identifier.  If <head>
 *   is non-NULL, the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(ph, id, )


/***
 * NAME
 *   flt_otel_conf_ph_free - conf_ph structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_ph_free(struct flt_otel_conf_ph **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_ph structure and its contents,
 *   then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(ph, id,
	FLT_OTEL_DBG_CONF_HDR("- conf_ph free ", *ptr, id);
)


/***
 * NAME
 *   flt_otel_conf_sample_expr_init - conf_sample_expr structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_sample_expr *flt_otel_conf_sample_expr_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_sample_expr structure.  The <id> string is
 *   duplicated and stored as the expression value.  If <head> is non-NULL, the
 *   structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(sample_expr, fmt_expr, )


/***
 * NAME
 *   flt_otel_conf_sample_expr_free - conf_sample_expr structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_sample_expr_free(struct flt_otel_conf_sample_expr **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_sample_expr structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(sample_expr, fmt_expr,
	FLT_OTEL_DBG_CONF_SAMPLE_EXPR("- conf_sample_expr free ", *ptr);

	release_sample_expr((*ptr)->expr);
)


/***
 * NAME
 *   flt_otel_conf_sample_init - conf_sample structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_sample *flt_otel_conf_sample_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_sample structure.  The <id> string is
 *   duplicated and stored as the sample key.  If <head> is non-NULL, the
 *   structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(sample, key,
	LIST_INIT(&(retptr->exprs));
	lf_expr_init(&(retptr->lf_expr));
)


/***
 * NAME
 *   flt_otel_conf_sample_init_ex - extended sample initialization
 *
 * SYNOPSIS
 *   struct flt_otel_conf_sample *flt_otel_conf_sample_init_ex(const char **args, int idx, int n, const struct otelc_value *extra, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   args  - configuration line arguments array
 *   idx   - position where sample value starts
 *   n     - maximum number of arguments to concatenate (0 means all)
 *   extra - optional extra data (event name or status code)
 *   line  - configuration file line number
 *   head  - list to append to (or NULL)
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Creates and initializes a conf_sample structure with extended data.  Calls
 *   flt_otel_conf_sample_init() with <args[idx - 1]> as the sample key to
 *   create the base structure, copies <extra> data (event name string or status
 *   code integer), concatenates the remaining arguments into the sample value
 *   string, and counts the number of sample expressions.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
struct flt_otel_conf_sample *flt_otel_conf_sample_init_ex(const char **args, int idx, int n, const struct otelc_value *extra, int line, struct list *head, char **err)
{
	struct flt_otel_conf_sample *retptr = NULL;

	OTELC_FUNC("%p, %d, %d, %p, %d, %p, %p:%p", args, idx, n, extra, line, head, OTELC_DPTR_ARGS(err));

	OTELC_DBG_VALUE(DEBUG, "extra ", extra);

	/* Ensure the sample value is present in the args[] array. */
	if (flt_otel_args_count(args) <= idx) {
		FLT_OTEL_ERR("'%s' : too few arguments", args[0]);

		OTELC_RETURN_PTR(retptr);
	}

	/* The sample key is located at the idx location of the args[] field. */
	retptr = flt_otel_conf_sample_init(args[idx - 1], line, head, err);
	if (retptr == NULL)
		OTELC_RETURN_PTR(retptr);

	if ((extra == NULL) || (extra->u_type == OTELC_VALUE_NULL)) {
		/*
		 * Do nothing - sample extra data is not set or initialized,
		 * which means it is not used.
		 */
	}
	else if (extra->u_type == OTELC_VALUE_STRING) {
		retptr->extra.u_type       = OTELC_VALUE_DATA;
		retptr->extra.u.value_data = OTELC_STRDUP(extra->u.value_string);
		if (retptr->extra.u.value_data == NULL) {
			FLT_OTEL_ERR("out of memory");
			flt_otel_conf_sample_free(&retptr);

			OTELC_RETURN_PTR(retptr);
		}
	}
	else if (extra->u_type == OTELC_VALUE_INT32) {
		retptr->extra.u_type        = extra->u_type;
		retptr->extra.u.value_int32 = extra->u.value_int32;
	}
	else {
		FLT_OTEL_ERR("invalid sample extra data type: %d", extra->u_type);
		flt_otel_conf_sample_free(&retptr);

		OTELC_RETURN_PTR(retptr);
	}

	/* The sample value starts in the args[] array after the key. */
	retptr->num_exprs = flt_otel_args_concat(args, idx, n, &(retptr->fmt_string));
	if (retptr->num_exprs == FLT_OTEL_RET_ERROR) {
		FLT_OTEL_ERR("out of memory");
		flt_otel_conf_sample_free(&retptr);

		OTELC_RETURN_PTR(retptr);
	}

	FLT_OTEL_DBG_CONF_SAMPLE("- conf_sample init ", retptr);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_conf_sample_free - conf_sample structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_sample_free(struct flt_otel_conf_sample **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_sample structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(sample, key,
	FLT_OTEL_DBG_CONF_SAMPLE("- conf_sample free ", *ptr);

	OTELC_SFREE((*ptr)->fmt_string);
	if ((*ptr)->extra.u_type == OTELC_VALUE_DATA)
		OTELC_SFREE((*ptr)->extra.u.value_data);
	FLT_OTEL_LIST_DESTROY(sample_expr, &((*ptr)->exprs));
	lf_expr_deinit(&((*ptr)->lf_expr));
)


/***
 * NAME
 *   flt_otel_conf_context_init - conf_context structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_context *flt_otel_conf_context_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_context structure.  The <id> string is
 *   duplicated and stored as the context identifier.  If <head> is non-NULL,
 *   the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(context, id, )


/***
 * NAME
 *   flt_otel_conf_context_free - conf_context structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_context_free(struct flt_otel_conf_context **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_context structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(context, id,
	FLT_OTEL_DBG_CONF_HDR("- conf_context free ", *ptr, id);
)


/***
 * NAME
 *   flt_otel_conf_span_init - conf_span structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_span *flt_otel_conf_span_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_span structure with empty lists for links,
 *   attributes, events, baggages, and statuses.  The <id> string is duplicated
 *   and stored as the span name.  If <head> is non-NULL, the structure is
 *   appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(span, id,
	LIST_INIT(&(retptr->links));
	LIST_INIT(&(retptr->attributes));
	LIST_INIT(&(retptr->events));
	LIST_INIT(&(retptr->baggages));
	LIST_INIT(&(retptr->statuses));
)


/***
 * NAME
 *   flt_otel_conf_span_free - conf_span structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_span_free(struct flt_otel_conf_span **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_span structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(span, id,
	FLT_OTEL_DBG_CONF_HDR("- conf_span free ", *ptr, id);

	OTELC_SFREE((*ptr)->ref_id);
	OTELC_SFREE((*ptr)->ctx_id);
	FLT_OTEL_LIST_DESTROY(link, &((*ptr)->links));
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->attributes));
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->events));
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->baggages));
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->statuses));
)


/***
 * NAME
 *   flt_otel_conf_instrument_init - conf_instrument structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_instrument *flt_otel_conf_instrument_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_instrument structure.  Sets the instrument
 *   type and meter index to OTELC_METRIC_INSTRUMENT_UNSET and initializes the
 *   samples list.  The <id> string is duplicated and stored as the instrument
 *   name.  If <head> is non-NULL, the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(instrument, id,
	retptr->idx       = OTELC_METRIC_INSTRUMENT_UNSET;
	retptr->type      = OTELC_METRIC_INSTRUMENT_UNSET;
	retptr->aggr_type = OTELC_METRIC_AGGREGATION_UNSET;
	LIST_INIT(&(retptr->samples));
)


/***
 * NAME
 *   flt_otel_conf_instrument_free - conf_instrument structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_instrument_free(struct flt_otel_conf_instrument **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_instrument structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(instrument, id,
	FLT_OTEL_DBG_CONF_INSTRUMENT("- conf_instrument free ", *ptr);

	OTELC_SFREE((*ptr)->description);
	OTELC_SFREE((*ptr)->unit);
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->samples));
	OTELC_SFREE((*ptr)->bounds);
	otelc_kv_destroy(&((*ptr)->attr), (*ptr)->attr_len);
)


/***
 * NAME
 *   flt_otel_conf_log_record_init - conf_log_record structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_log_record *flt_otel_conf_log_record_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_log_record structure.  Initializes the
 *   sample expressions list.  The <id> string is required by the macro but is
 *   not used directly; the severity level is stored separately.  If <head> is
 *   non-NULL, the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(log_record, id,
	LIST_INIT(&(retptr->samples));
)


/***
 * NAME
 *   flt_otel_conf_log_record_free - conf_log_record structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_log_record_free(struct flt_otel_conf_log_record **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_log_record structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(log_record, id,
	FLT_OTEL_DBG_CONF_LOG_RECORD("- conf_log_record free ", *ptr);

	OTELC_SFREE((*ptr)->event_name);
	OTELC_SFREE((*ptr)->span);
	otelc_kv_destroy(&((*ptr)->attr), (*ptr)->attr_len);
	FLT_OTEL_LIST_DESTROY(sample, &((*ptr)->samples));
)


/***
 * NAME
 *   flt_otel_conf_scope_init - conf_scope structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_scope *flt_otel_conf_scope_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_scope structure with empty lists for ACLs,
 *   contexts, spans, spans_to_finish, and instruments.  The <id> string is
 *   duplicated and stored as the scope name.  If <head> is non-NULL, the
 *   structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(scope, id,
	LIST_INIT(&(retptr->acls));
	LIST_INIT(&(retptr->contexts));
	LIST_INIT(&(retptr->spans));
	LIST_INIT(&(retptr->spans_to_finish));
	LIST_INIT(&(retptr->instruments));
	LIST_INIT(&(retptr->log_records));
)


/***
 * NAME
 *   flt_otel_conf_scope_free - conf_scope structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_scope_free(struct flt_otel_conf_scope **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_scope structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(scope, id,
	struct acl *acl;
	struct acl *aclback;

	FLT_OTEL_DBG_CONF_SCOPE("- conf_scope free ", *ptr);

	list_for_each_entry_safe(acl, aclback, &((*ptr)->acls), list) {
		prune_acl(acl);
		FLT_OTEL_LIST_DEL(&(acl->list));
		OTELC_SFREE(acl);
	}
	free_acl_cond((*ptr)->cond);
	FLT_OTEL_LIST_DESTROY(context, &((*ptr)->contexts));
	FLT_OTEL_LIST_DESTROY(span, &((*ptr)->spans));
	FLT_OTEL_LIST_DESTROY(str, &((*ptr)->spans_to_finish));
	FLT_OTEL_LIST_DESTROY(instrument, &((*ptr)->instruments));
	FLT_OTEL_LIST_DESTROY(log_record, &((*ptr)->log_records));
)


/***
 * NAME
 *   flt_otel_conf_group_init - conf_group structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_group *flt_otel_conf_group_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_group structure with an empty placeholder
 *   scope list.  The <id> string is duplicated and stored as the group name.
 *   If <head> is non-NULL, the structure is appended to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(group, id,
	LIST_INIT(&(retptr->ph_scopes));
)


/***
 * NAME
 *   flt_otel_conf_group_free - conf_group structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_group_free(struct flt_otel_conf_group **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_group structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(group, id,
	FLT_OTEL_DBG_CONF_GROUP("- conf_group free ", *ptr);

	FLT_OTEL_LIST_DESTROY(ph_scope, &((*ptr)->ph_scopes));
)


/***
 * NAME
 *   flt_otel_conf_instr_init - conf_instr structure allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf_instr *flt_otel_conf_instr_init(const char *id, int line, struct list *head, char **err)
 *
 * ARGUMENTS
 *   id   - identifier string to duplicate
 *   line - configuration file line number
 *   head - list to append to (or NULL)
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates and initializes a conf_instr (instrumentation) structure.  Sets
 *   the default rate limit to 100%, initializes the proxy_log for logger
 *   support, and creates empty lists for ACLs, placeholder groups, and
 *   placeholder scopes.  The <id> string is duplicated and stored as the
 *   instrumentation name.  If <head> is non-NULL, the structure is appended
 *   to the list.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
FLT_OTEL_CONF_FUNC_INIT(instr, id,
	retptr->rate_limit = FLT_OTEL_FLOAT_U32(100.0);
	init_new_proxy(&(retptr->proxy_log));
	LIST_INIT(&(retptr->acls));
	LIST_INIT(&(retptr->ph_groups));
	LIST_INIT(&(retptr->ph_scopes));
)


/***
 * NAME
 *   flt_otel_conf_instr_free - conf_instr structure deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_instr_free(struct flt_otel_conf_instr **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf_instr structure and its
 *   contents, then removes it from the list of structures of that type.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
FLT_OTEL_CONF_FUNC_FREE(instr, id,
	struct acl    *acl;
	struct acl    *aclback;
	struct logger *logger;
	struct logger *loggerback;

	FLT_OTEL_DBG_CONF_INSTR("- conf_instr free ", *ptr);

	OTELC_SFREE((*ptr)->config);
	OTELC_DBG(NOTICE, "- deleting acls list %s", flt_otel_list_dump(&((*ptr)->acls)));
	list_for_each_entry_safe(acl, aclback, &((*ptr)->acls), list) {
		prune_acl(acl);
		FLT_OTEL_LIST_DEL(&(acl->list));
		OTELC_SFREE(acl);
	}
	OTELC_DBG(NOTICE, "- deleting proxy_log.loggers list %s", flt_otel_list_dump(&((*ptr)->proxy_log.loggers)));
	list_for_each_entry_safe(logger, loggerback, &((*ptr)->proxy_log.loggers), list) {
		LIST_DELETE(&(logger->list));
		ha_free(&logger);
	}
	FLT_OTEL_LIST_DESTROY(ph_group, &((*ptr)->ph_groups));
	FLT_OTEL_LIST_DESTROY(ph_scope, &((*ptr)->ph_scopes));
)


/***
 * NAME
 *   flt_otel_conf_init - top-level filter configuration allocation
 *
 * SYNOPSIS
 *   struct flt_otel_conf *flt_otel_conf_init(struct proxy *px)
 *
 * ARGUMENTS
 *   px - proxy instance to associate with
 *
 * DESCRIPTION
 *   Allocates and initializes the top-level flt_otel_conf structure.  Stores
 *   the <px> proxy reference and creates empty group and scope lists.
 *
 * RETURN VALUE
 *   Returns a pointer to the initialized structure, or NULL on failure.
 */
struct flt_otel_conf *flt_otel_conf_init(struct proxy *px)
{
	struct flt_otel_conf *retptr;

	OTELC_FUNC("%p", px);

	retptr = OTELC_CALLOC(1, sizeof(*retptr));
	if (retptr == NULL)
		OTELC_RETURN_PTR(retptr);

	retptr->proxy = px;
	LIST_INIT(&(retptr->groups));
	LIST_INIT(&(retptr->scopes));
	LIST_INIT(&(retptr->smp_args));

	FLT_OTEL_DBG_CONF("- conf init ", retptr);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_conf_free - top-level filter configuration deallocation
 *
 * SYNOPSIS
 *   void flt_otel_conf_free(struct flt_otel_conf **ptr)
 *
 * ARGUMENTS
 *   ptr - a pointer to the address of a structure
 *
 * DESCRIPTION
 *   Deallocates memory used by the flt_otel_conf structure and its contents.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_conf_free(struct flt_otel_conf **ptr)
{
	struct arg_list *cur, *back;

	OTELC_FUNC("%p:%p", OTELC_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		OTELC_RETURN();

	FLT_OTEL_DBG_CONF("- conf free ", *ptr);

	OTELC_SFREE((*ptr)->id);
	OTELC_SFREE((*ptr)->cfg_file);
	flt_otel_conf_instr_free(&((*ptr)->instr));
	FLT_OTEL_LIST_DESTROY(group, &((*ptr)->groups));
	FLT_OTEL_LIST_DESTROY(scope, &((*ptr)->scopes));
	/* Free any unresolved OTEL sample fetch args (error path). */
	list_for_each_entry_safe(cur, back, &((*ptr)->smp_args), list) {
		LIST_DELETE(&(cur->list));
		ha_free(&cur);
	}
	OTELC_SFREE_CLEAR(*ptr);

	OTELC_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
