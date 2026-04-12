/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


struct pool_head *pool_head_otel_scope_span __read_mostly = NULL;
struct pool_head *pool_head_otel_scope_context __read_mostly = NULL;
struct pool_head *pool_head_otel_runtime_context __read_mostly = NULL;
struct pool_head *pool_head_otel_span_context __read_mostly = NULL;

#ifdef USE_POOL_OTEL_SCOPE_SPAN
REGISTER_POOL(&pool_head_otel_scope_span, "otel_scope_span", sizeof(struct flt_otel_scope_span));
#endif
#ifdef USE_POOL_OTEL_SCOPE_CONTEXT
REGISTER_POOL(&pool_head_otel_scope_context, "otel_scope_context", sizeof(struct flt_otel_scope_context));
#endif
#ifdef USE_POOL_OTEL_RUNTIME_CONTEXT
REGISTER_POOL(&pool_head_otel_runtime_context, "otel_runtime_context", sizeof(struct flt_otel_runtime_context));
#endif
#ifdef USE_POOL_OTEL_SPAN_CONTEXT
REGISTER_POOL(&pool_head_otel_span_context, "otel_span_context", MAX(sizeof(struct otelc_span), sizeof(struct otelc_span_context)));
#endif


/***
 * NAME
 *   flt_otel_pool_alloc - pool-aware memory allocation
 *
 * SYNOPSIS
 *   void *flt_otel_pool_alloc(struct pool_head *pool, size_t size, bool flag_clear, char **err)
 *
 * ARGUMENTS
 *   pool       - HAProxy memory pool to allocate from (or NULL for heap)
 *   size       - number of bytes to allocate
 *   flag_clear - whether to zero-fill the allocated memory
 *   err        - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates <size> bytes of memory from the HAProxy memory <pool>.  If <pool>
 *   is NULL, the allocation falls back to the heap via OTELC_MALLOC().  When
 *   <flag_clear> is set, the allocated memory is zero-filled.  On allocation
 *   failure, an error message is stored via <err>.
 *
 * RETURN VALUE
 *   Returns a pointer to the allocated memory, or NULL on failure.
 */
void *flt_otel_pool_alloc(struct pool_head *pool, size_t size, bool flag_clear, char **err)
{
	void *retptr;

	OTELC_FUNC("%p, %zu, %hhu, %p:%p", pool, size, flag_clear, OTELC_DPTR_ARGS(err));

	if (pool != NULL) {
		retptr = pool_alloc(pool);
		if (retptr != NULL)
			OTELC_DBG(NOTICE, "POOL_ALLOC: %s:%d(%p %zu)", __func__, __LINE__, retptr, FLT_OTEL_DEREF(pool, size, size));
	} else {
		retptr = OTELC_MALLOC(size);
	}

	if (retptr == NULL)
		FLT_OTEL_ERR("out of memory");
	else if (flag_clear)
		(void)memset(retptr, 0, size);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_pool_strndup - pool-aware string duplication
 *
 * SYNOPSIS
 *   void *flt_otel_pool_strndup(struct pool_head *pool, const char *s, size_t size, char **err)
 *
 * ARGUMENTS
 *   pool - HAProxy memory pool to allocate from (or NULL for heap)
 *   s    - source string to duplicate
 *   size - maximum number of characters to copy
 *   err  - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Duplicates up to <size> characters from the string <s> using the HAProxy
 *   memory <pool>.  If <pool> is NULL, the duplication falls back to
 *   OTELC_STRNDUP().  When using a pool, the copy is truncated to <pool>->size-1
 *   bytes and null-terminated.
 *
 * RETURN VALUE
 *   Returns a pointer to the duplicated string, or NULL on failure.
 */
void *flt_otel_pool_strndup(struct pool_head *pool, const char *s, size_t size, char **err)
{
	void *retptr;

	OTELC_FUNC("%p, \"%.*s\", %zu, %p:%p", pool, (int)size, s, size, OTELC_DPTR_ARGS(err));

	if (pool != NULL) {
		retptr = pool_alloc(pool);
		if (retptr != NULL) {
			(void)memcpy(retptr, s, MIN(pool->size - 1, size));

			((uint8_t *)retptr)[MIN(pool->size - 1, size)] = '\0';
		}
	} else {
		retptr = OTELC_STRNDUP(s, size);
	}

	if (retptr != NULL)
		OTELC_DBG(NOTICE, "POOL_STRNDUP: %s:%d(%p %zu)", __func__, __LINE__, retptr, FLT_OTEL_DEREF(pool, size, size));
	else
		FLT_OTEL_ERR("out of memory");

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_pool_free - pool-aware memory deallocation
 *
 * SYNOPSIS
 *   void flt_otel_pool_free(struct pool_head *pool, void **ptr)
 *
 * ARGUMENTS
 *   pool - HAProxy memory pool to return memory to (or NULL for heap)
 *   ptr  - indirect pointer to the memory to free
 *
 * DESCRIPTION
 *   Returns memory referenced by <*ptr> to the HAProxy memory <pool>.  If
 *   <pool> is NULL, the memory is freed via OTELC_SFREE().  The pointer <*ptr>
 *   is set to NULL after freeing.  If <ptr> is NULL or <*ptr> is already NULL,
 *   the function returns immediately.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_pool_free(struct pool_head *pool, void **ptr)
{
	OTELC_FUNC("%p, %p:%p", pool, OTELC_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		OTELC_RETURN();

	OTELC_DBG(NOTICE, "POOL_FREE: %s:%d(%p %u)", __func__, __LINE__, *ptr, FLT_OTEL_DEREF(pool, size, 0));

	if (pool != NULL)
		pool_free(pool, *ptr);
	else
		OTELC_SFREE(*ptr);

	*ptr = NULL;

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_pool_init - OTel filter memory pool initialization
 *
 * SYNOPSIS
 *   int flt_otel_pool_init(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Initializes all memory pools used by the OTel filter.  Each pool is
 *   created only when the corresponding USE_POOL_OTEL_* macro is defined.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK on success, FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_pool_init(void)
{
	int retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("");

#ifdef USE_POOL_OTEL_SCOPE_SPAN
	FLT_OTEL_POOL_INIT(pool_head_otel_scope_span, "otel_scope_span", sizeof(struct flt_otel_scope_span), retval);
#endif
#ifdef USE_POOL_OTEL_SCOPE_CONTEXT
	FLT_OTEL_POOL_INIT(pool_head_otel_scope_context, "otel_scope_context", sizeof(struct flt_otel_scope_context), retval);
#endif
#ifdef USE_POOL_OTEL_RUNTIME_CONTEXT
	FLT_OTEL_POOL_INIT(pool_head_otel_runtime_context, "otel_runtime_context", sizeof(struct flt_otel_runtime_context), retval);
#endif
#ifdef USE_POOL_OTEL_SPAN_CONTEXT
	FLT_OTEL_POOL_INIT(pool_head_otel_span_context, "otel_span_context", OTELC_MAX(sizeof(struct otelc_span), sizeof(struct otelc_span_context)), retval);
#endif

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_pool_destroy - OTel filter memory pool destruction
 *
 * SYNOPSIS
 *   void flt_otel_pool_destroy(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Destroys all memory pools used by the OTel filter.  Each pool is
 *   destroyed only when the corresponding USE_POOL_OTEL_* macro is defined.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_pool_destroy(void)
{
	OTELC_FUNC("");

#ifdef USE_POOL_OTEL_SCOPE_SPAN
	FLT_OTEL_POOL_DESTROY(pool_head_otel_scope_span);
#endif
#ifdef USE_POOL_OTEL_SCOPE_CONTEXT
	FLT_OTEL_POOL_DESTROY(pool_head_otel_scope_context);
#endif
#ifdef USE_POOL_OTEL_RUNTIME_CONTEXT
	FLT_OTEL_POOL_DESTROY(pool_head_otel_runtime_context);
#endif
#ifdef USE_POOL_OTEL_SPAN_CONTEXT
	FLT_OTEL_POOL_DESTROY(pool_head_otel_span_context);
#endif

	OTELC_RETURN();
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_pool_info - debug pool sizes logging
 *
 * SYNOPSIS
 *   void flt_otel_pool_info(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Logs the sizes of all registered HAProxy memory pools used by the OTel
 *   filter (buffer, trash, scope_span, scope_context, runtime_context).
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_pool_info(void)
{
	OTELC_DBG(NOTICE, "--- pool info ----------");

	/*
	 * In case we have some error in the configuration file,
	 * it is possible that this pool was not initialized.
	 */
#ifdef USE_POOL_BUFFER
	OTELC_DBG(NOTICE, "  buffer: %p %u", pool_head_buffer, FLT_OTEL_DEREF(pool_head_buffer, size, 0));
#endif
#ifdef USE_TRASH_CHUNK
	OTELC_DBG(NOTICE, "  trash: %p %u", pool_head_trash, FLT_OTEL_DEREF(pool_head_trash, size, 0));
#endif

#ifdef USE_POOL_OTEL_SCOPE_SPAN
	OTELC_DBG(NOTICE, "  otel_scope_span: %p %u", pool_head_otel_scope_span, FLT_OTEL_DEREF(pool_head_otel_scope_span, size, 0));
#endif
#ifdef USE_POOL_OTEL_SCOPE_CONTEXT
	OTELC_DBG(NOTICE, "  otel_scope_context: %p %u", pool_head_otel_scope_context, FLT_OTEL_DEREF(pool_head_otel_scope_context, size, 0));
#endif
#ifdef USE_POOL_OTEL_RUNTIME_CONTEXT
	OTELC_DBG(NOTICE, "  otel_runtime_context: %p %u", pool_head_otel_runtime_context, FLT_OTEL_DEREF(pool_head_otel_runtime_context, size, 0));
#endif
#ifdef USE_POOL_OTEL_SPAN_CONTEXT
	OTELC_DBG(NOTICE, "  otel_span_context: %p %u", pool_head_otel_span_context, FLT_OTEL_DEREF(pool_head_otel_span_context, size, 0));
#endif
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_trash_alloc - trash buffer allocation
 *
 * SYNOPSIS
 *   struct buffer *flt_otel_trash_alloc(bool flag_clear, char **err)
 *
 * ARGUMENTS
 *   flag_clear - whether to zero-fill the buffer area
 *   err        - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Allocates a temporary buffer chunk for use as scratch space.  When
 *   USE_TRASH_CHUNK is defined, the buffer is obtained via alloc_trash_chunk();
 *   otherwise, a buffer structure and its data area are allocated from the heap
 *   using global.tune.bufsize as the buffer size.  When <flag_clear> is set,
 *   the buffer's data area is zero-filled.
 *
 * RETURN VALUE
 *   Returns a pointer to the allocated buffer, or NULL on failure.
 */
struct buffer *flt_otel_trash_alloc(bool flag_clear, char **err)
{
	struct buffer *retptr;

	OTELC_FUNC("%hhu, %p:%p", flag_clear, OTELC_DPTR_ARGS(err));

#ifdef USE_TRASH_CHUNK
	retptr = alloc_trash_chunk();
	if (retptr != NULL)
		OTELC_DBG(NOTICE, "TRASH_ALLOC: %s:%d(%p %zu)", __func__, __LINE__, retptr, retptr->size);
#else
	retptr = OTELC_MALLOC(sizeof(*retptr));
	if (retptr != NULL) {
		chunk_init(retptr, OTELC_MALLOC(global.tune.bufsize), global.tune.bufsize);
		if (retptr->area == NULL)
			OTELC_SFREE_CLEAR(retptr);
		else
			*(retptr->area) = '\0';
	}
#endif

	if (retptr == NULL)
		FLT_OTEL_ERR("out of memory");
	else if (flag_clear)
		(void)memset(retptr->area, 0, retptr->size);

	OTELC_RETURN_PTR(retptr);
}


/***
 * NAME
 *   flt_otel_trash_free - trash buffer deallocation
 *
 * SYNOPSIS
 *   void flt_otel_trash_free(struct buffer **ptr)
 *
 * ARGUMENTS
 *   ptr - indirect pointer to the buffer to free
 *
 * DESCRIPTION
 *   Frees a trash buffer chunk previously allocated by flt_otel_trash_alloc().
 *   When USE_TRASH_CHUNK is defined, the buffer is freed via
 *   free_trash_chunk(); otherwise, both the data area and the buffer structure
 *   are freed individually.  The pointer <*ptr> is set to NULL after freeing.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_trash_free(struct buffer **ptr)
{
	OTELC_FUNC("%p:%p", OTELC_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		OTELC_RETURN();

	OTELC_DBG(NOTICE, "TRASH_FREE: %s:%d(%p %zu)", __func__, __LINE__, *ptr, (*ptr)->size);

#ifdef USE_TRASH_CHUNK
	free_trash_chunk(*ptr);
#else
	OTELC_SFREE((*ptr)->area);
	OTELC_SFREE(*ptr);
#endif

	*ptr = NULL;

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
