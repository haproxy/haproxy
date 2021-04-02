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


/***
 * NAME
 *   flt_ot_conf_hdr_init -
 *
 * ARGUMENTS
 *   size    -
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
static void *flt_ot_conf_hdr_init(size_t size, const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_hdr *retptr = NULL, *ptr;

	FLT_OT_FUNC("%zu, \"%s\", %d, %p, %p:%p", size, id, linenum, head, FLT_OT_DPTR_ARGS(err));

	if (head != NULL)
		list_for_each_entry(ptr, head, list)
			if (strcmp(ptr->id, id) == 0) {
				FLT_OT_ERR("'%s' : already defined", id);

				FLT_OT_RETURN(retptr);
			}

	retptr = FLT_OT_CALLOC(1, size);
	if (retptr != NULL) {
		retptr->id_len = strlen(id);
		if (retptr->id_len >= FLT_OT_ID_MAXLEN)
			FLT_OT_ERR("'%s' : name too long", id);
		else
			retptr->id = FLT_OT_STRDUP(id);

		if (retptr->id == NULL)
			FLT_OT_FREE_CLEAR(retptr);
	}

	if (retptr != NULL) {
		retptr->cfg_line = linenum;

		if (head != NULL)
			LIST_ADDQ(head, &(retptr->list));
	} else {
		FLT_OT_ERR("out of memory");
	}

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_ph_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_ph *flt_ot_conf_ph_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_ph *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr != NULL)
		FLT_OT_DBG_CONF_PH("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_ph_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_ph_free(struct flt_ot_conf_ph **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_PH("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_sample_expr_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_sample_expr *flt_ot_conf_sample_expr_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_sample_expr *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr != NULL)
		FLT_OT_DBG_CONF_SAMPLE_EXPR("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_sample_expr_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_sample_expr_free(struct flt_ot_conf_sample_expr **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_SAMPLE_EXPR("- free ", *ptr);

	FLT_OT_FREE((*ptr)->value);
	release_sample_expr((*ptr)->expr);
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_sample_init -
 *
 * ARGUMENTS
 *   args    -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_sample *flt_ot_conf_sample_init(char **args, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_sample *retptr;

	FLT_OT_FUNC("%p, %d, %p, %p:%p", args, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), args[1], linenum, head, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	flt_ot_args_to_str(args, 2, &(retptr->value));
	if (retptr->value == NULL) {
		FLT_OT_FREE_CLEAR(retptr);

		FLT_OT_RETURN(retptr);
	}

	retptr->num_exprs = flt_ot_args_count(args) - 2;
	LIST_INIT(&(retptr->exprs));

	FLT_OT_DBG_CONF_SAMPLE("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_sample_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_sample_free(struct flt_ot_conf_sample **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_SAMPLE("- free ", *ptr);

	FLT_OT_FREE((*ptr)->key);
	FLT_OT_FREE((*ptr)->value);
	FLT_OT_LIST_DESTROY(sample_expr, &((*ptr)->exprs));
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_str_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_str *flt_ot_conf_str_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_str *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr != NULL)
		FLT_OT_DBG_CONF_STR("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_str_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_str_free(struct flt_ot_conf_str **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_STR("- free ", *ptr);

	FLT_OT_FREE((*ptr)->str);
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_context_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_context *flt_ot_conf_context_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_context *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr != NULL)
		FLT_OT_DBG_CONF_CONTEXT("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_context_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_context_free(struct flt_ot_conf_context **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_CONTEXT("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_span_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_span *flt_ot_conf_span_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_span *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	LIST_INIT(&(retptr->tags));
	LIST_INIT(&(retptr->logs));
	LIST_INIT(&(retptr->baggages));

	FLT_OT_DBG_CONF_SPAN("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_span_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_span_free(struct flt_ot_conf_span **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_SPAN("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_FREE((*ptr)->ref_id);
	FLT_OT_FREE((*ptr)->ctx_id);
	FLT_OT_LIST_DESTROY(sample, &((*ptr)->tags));
	FLT_OT_LIST_DESTROY(sample, &((*ptr)->logs));
	FLT_OT_LIST_DESTROY(sample, &((*ptr)->baggages));
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_scope_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_scope *flt_ot_conf_scope_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_scope *retptr = NULL;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	LIST_INIT(&(retptr->acls));
	LIST_INIT(&(retptr->contexts));
	LIST_INIT(&(retptr->spans));
	LIST_INIT(&(retptr->finish));

	FLT_OT_DBG_CONF_SCOPE("- init ", retptr);

	FLT_OT_RETURN(retptr);
}

/***
 * NAME
 *   flt_ot_conf_scope_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_scope_free(struct flt_ot_conf_scope **ptr)
{
	struct acl *acl, *aclback;

	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_SCOPE("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	list_for_each_entry_safe(acl, aclback, &((*ptr)->acls), list) {
		prune_acl(acl);
		FLT_OT_LIST_DEL(&(acl->list));
		FLT_OT_FREE(acl);
	}
	if ((*ptr)->cond != NULL) {
		prune_acl_cond((*ptr)->cond);
		FLT_OT_FREE((*ptr)->cond);
	}
	FLT_OT_LIST_DESTROY(context, &((*ptr)->contexts));
	FLT_OT_LIST_DESTROY(span, &((*ptr)->spans));
	FLT_OT_LIST_DESTROY(str, &((*ptr)->finish));
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_group_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   head    -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_group *flt_ot_conf_group_init(const char *id, int linenum, struct list *head, char **err)
{
	struct flt_ot_conf_group *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p, %p:%p", id, linenum, head, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, head, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	LIST_INIT(&(retptr->ph_scopes));

	FLT_OT_DBG_CONF_GROUP("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_group_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_group_free(struct flt_ot_conf_group **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_GROUP("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_LIST_DESTROY(ph_scope, &((*ptr)->ph_scopes));
	FLT_OT_LIST_DEL(&((*ptr)->list));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_tracer_init -
 *
 * ARGUMENTS
 *   id      -
 *   linenum -
 *   err     -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf_tracer *flt_ot_conf_tracer_init(const char *id, int linenum, char **err)
{
	struct flt_ot_conf_tracer *retptr;

	FLT_OT_FUNC("\"%s\", %d, %p:%p", id, linenum, FLT_OT_DPTR_ARGS(err));

	retptr = flt_ot_conf_hdr_init(sizeof(*retptr), id, linenum, NULL, err);
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	retptr->rate_limit = FLT_OT_FLOAT_U32(FLT_OT_RATE_LIMIT_MAX, FLT_OT_RATE_LIMIT_MAX);
	init_new_proxy(&(retptr->proxy_log));
	LIST_INIT(&(retptr->acls));
	LIST_INIT(&(retptr->ph_groups));
	LIST_INIT(&(retptr->ph_scopes));

	FLT_OT_DBG_CONF_TRACER("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_tracer_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_tracer_free(struct flt_ot_conf_tracer **ptr)
{
	struct acl    *acl, *aclback;
	struct logsrv *logsrv, *logsrvback;

	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF_TRACER("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_FREE((*ptr)->config);
	FLT_OT_FREE((*ptr)->plugin);
	FLT_OT_DBG(2, "- deleting acls list %s", flt_ot_list_debug(&((*ptr)->acls)));
	list_for_each_entry_safe(acl, aclback, &((*ptr)->acls), list) {
		prune_acl(acl);
		FLT_OT_LIST_DEL(&(acl->list));
		FLT_OT_FREE(acl);
	}
	FLT_OT_DBG(2, "- deleting proxy_log.logsrvs list %s", flt_ot_list_debug(&((*ptr)->proxy_log.logsrvs)));
	list_for_each_entry_safe(logsrv, logsrvback, &((*ptr)->proxy_log.logsrvs), list) {
		LIST_DEL(&(logsrv->list));
		FLT_OT_FREE(logsrv);
	}
	FLT_OT_LIST_DESTROY(ph_group, &((*ptr)->ph_groups));
	FLT_OT_LIST_DESTROY(ph_scope, &((*ptr)->ph_scopes));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_conf_init -
 *
 * ARGUMENTS
 *   px -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
struct flt_ot_conf *flt_ot_conf_init(struct proxy *px)
{
	struct flt_ot_conf *retptr;

	FLT_OT_FUNC("%p", px);

	retptr = FLT_OT_CALLOC(1, sizeof(*retptr));
	if (retptr == NULL)
		FLT_OT_RETURN(retptr);

	retptr->proxy = px;
	LIST_INIT(&(retptr->groups));
	LIST_INIT(&(retptr->scopes));

	FLT_OT_DBG_CONF("- init ", retptr);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_conf_free -
 *
 * ARGUMENTS
 *   ptr -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_conf_free(struct flt_ot_conf **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG_CONF("- free ", *ptr);

	FLT_OT_FREE((*ptr)->id);
	FLT_OT_FREE((*ptr)->cfg_file);
	flt_ot_conf_tracer_free(&((*ptr)->tracer));
	FLT_OT_LIST_DESTROY(group, &((*ptr)->groups));
	FLT_OT_LIST_DESTROY(scope, &((*ptr)->scopes));
	FLT_OT_FREE_CLEAR(*ptr);

	FLT_OT_RETURN();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
