/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_CONF_FUNCS_H_
#define _OTEL_CONF_FUNCS_H_

/*
 * Macro that generates a flt_otel_conf_<type>_init() function.  The generated
 * function allocates and initializes a configuration structure of the given
 * type, checks for duplicate names in the list, and optionally runs a custom
 * initializer body.
 */
#define FLT_OTEL_CONF_FUNC_INIT(_type_, _id_, _func_)                                                                         \
	struct flt_otel_conf_##_type_ *flt_otel_conf_##_type_##_init(const char *id, int line, struct list *head, char **err) \
	{                                                                                                                     \
		struct flt_otel_conf_##_type_ *retptr = NULL;                                                                 \
		struct flt_otel_conf_##_type_ *ptr;                                                                           \
		size_t                         _id_##_len;                                                                    \
		                                                                                                              \
		OTELC_FUNC("\"%s\", %d, %p, %p:%p", OTELC_STR_ARG(id), line, head, OTELC_DPTR_ARGS(err));                     \
		                                                                                                              \
		if ((id == NULL) || (*id == '\0')) {                                                                          \
			FLT_OTEL_ERR("name not set");                                                                         \
		                                                                                                              \
			OTELC_RETURN_PTR(retptr);                                                                             \
		}                                                                                                             \
		                                                                                                              \
		_id_##_len = strlen(id);                                                                                      \
		if (_id_##_len >= FLT_OTEL_ID_MAXLEN) {                                                                       \
			FLT_OTEL_ERR("'%s' : name too long", id);                                                             \
		                                                                                                              \
			OTELC_RETURN_PTR(retptr);                                                                             \
		}                                                                                                             \
		                                                                                                              \
		if (head != NULL)                                                                                             \
			list_for_each_entry(ptr, head, list)                                                                  \
				if (strcmp(ptr->_id_, id) == 0) {                                                             \
					FLT_OTEL_ERR("'%s' : already defined", id);                                           \
		                                                                                                              \
					OTELC_RETURN_PTR(retptr);                                                             \
				}                                                                                             \
		                                                                                                              \
		retptr = OTELC_CALLOC(1, sizeof(*retptr));                                                                    \
		if (retptr != NULL) {                                                                                         \
			retptr->cfg_line   = line;                                                                            \
			retptr->_id_##_len = _id_##_len;                                                                      \
			retptr->_id_       = OTELC_STRDUP(id);                                                                \
			if (retptr->_id_ != NULL) {                                                                           \
				if (head != NULL)                                                                             \
					LIST_APPEND(head, &(retptr->list));                                                   \
		                                                                                                              \
				FLT_OTEL_DBG_CONF_HDR("- conf_" #_type_ " init ", retptr, _id_);                              \
			}                                                                                                     \
			else                                                                                                  \
				OTELC_SFREE_CLEAR(retptr);                                                                    \
		}                                                                                                             \
		                                                                                                              \
		if (retptr != NULL) {                                                                                         \
			_func_                                                                                                \
		}                                                                                                             \
		                                                                                                              \
		if (retptr == NULL)                                                                                           \
			FLT_OTEL_ERR("out of memory");                                                                        \
		                                                                                                              \
		OTELC_RETURN_PTR(retptr);                                                                                     \
	}

/*
 * Macro that generates a flt_otel_conf_<type>_free() function.  The generated
 * function runs a custom cleanup body, then frees the name string, removes the
 * structure from its list, and frees the structure.
 */
#define FLT_OTEL_CONF_FUNC_FREE(_type_, _id_, _func_)                           \
	void flt_otel_conf_##_type_##_free(struct flt_otel_conf_##_type_ **ptr) \
	{                                                                       \
		OTELC_FUNC("%p:%p", OTELC_DPTR_ARGS(ptr));                      \
		                                                                \
		if ((ptr == NULL) || (*ptr == NULL))                            \
			OTELC_RETURN();                                         \
		                                                                \
		{ _func_ }                                                      \
		                                                                \
		OTELC_SFREE((*ptr)->_id_);                                      \
		FLT_OTEL_LIST_DEL(&((*ptr)->list));                             \
		OTELC_SFREE_CLEAR(*ptr);                                        \
		                                                                \
		OTELC_RETURN();                                                 \
	}


/* The FLT_OTEL_LIST_DESTROY() macro uses the following two definitions. */
#define flt_otel_conf_ph_group_free    flt_otel_conf_ph_free
#define flt_otel_conf_ph_scope_free    flt_otel_conf_ph_free

/* Declare init/free function prototypes for a configuration type. */
#define FLT_OTEL_CONF_FUNC_DECL(_type_)                                                                                        \
	struct flt_otel_conf_##_type_ *flt_otel_conf_##_type_##_init(const char *id, int line, struct list *head, char **err); \
	void                           flt_otel_conf_##_type_##_free(struct flt_otel_conf_##_type_ **ptr);

FLT_OTEL_CONF_FUNC_DECL(hdr)
FLT_OTEL_CONF_FUNC_DECL(str)
FLT_OTEL_CONF_FUNC_DECL(ph)
FLT_OTEL_CONF_FUNC_DECL(sample_expr)
FLT_OTEL_CONF_FUNC_DECL(sample)
FLT_OTEL_CONF_FUNC_DECL(context)
FLT_OTEL_CONF_FUNC_DECL(span)
FLT_OTEL_CONF_FUNC_DECL(scope)
FLT_OTEL_CONF_FUNC_DECL(group)
FLT_OTEL_CONF_FUNC_DECL(instr)

#endif /* _OTEL_CONF_FUNCS_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
