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
 *   flt_ot_pool_alloc -
 *
 * ARGUMENTS
 *   pool       -
 *   size       -
 *   flag_clear -
 *   err        -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
void *flt_ot_pool_alloc(struct pool_head *pool, size_t size, bool flag_clear, char **err)
{
	void *retptr;

	FLT_OT_FUNC("%p, %zu, %hhu, %p:%p", pool, size, flag_clear, FLT_OT_DPTR_ARGS(err));

	if (pool != NULL) {
		retptr = pool_alloc_dirty(pool);
		if (retptr != NULL)
			FLT_OT_DBG(2, "POOL_ALLOC: %s:%d(%p %zu)", __func__, __LINE__, retptr, FLT_OT_DEREF(pool, size, size));
	} else {
		retptr = FLT_OT_MALLOC(size);
	}

	if (retptr == NULL)
		FLT_OT_ERR("out of memory");
	else if (flag_clear)
		(void)memset(retptr, 0, size);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_pool_strndup -
 *
 * ARGUMENTS
 *   pool -
 *   s    -
 *   size -
 *   err  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
void *flt_ot_pool_strndup(struct pool_head *pool, const char *s, size_t size, char **err)
{
	void *retptr;

	FLT_OT_FUNC("%p, \"%.*s\", %zu, %p:%p", pool, (int)size, s, size, FLT_OT_DPTR_ARGS(err));

	if (pool != NULL) {
		retptr = pool_alloc_dirty(pool);
		if (retptr != NULL) {
			(void)memcpy(retptr, s, MIN(pool->size - 1, size));

			((uint8_t *)retptr)[MIN(pool->size - 1, size)] = '\0';
		}
	} else {
		retptr = FLT_OT_STRNDUP(s, size);
	}

	if (retptr != NULL)
		FLT_OT_DBG(2, "POOL_STRNDUP: %s:%d(%p %zu)", __func__, __LINE__, retptr, FLT_OT_DEREF(pool, size, size));
	else
		FLT_OT_ERR("out of memory");

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_pool_free -
 *
 * ARGUMENTS
 *   pool -
 *   ptr  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_pool_free(struct pool_head *pool, void **ptr)
{
	FLT_OT_FUNC("%p, %p:%p", pool, FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG(2, "POOL_FREE: %s:%d(%p %u)", __func__, __LINE__, *ptr, FLT_OT_DEREF(pool, size, 0));

	if (pool != NULL)
		pool_free(pool, *ptr);
	else
		FLT_OT_FREE(*ptr);

	*ptr = NULL;

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_trash_alloc -
 *
 * ARGUMENTS
 *   flag_clear -
 *   err        -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
struct buffer *flt_ot_trash_alloc(bool flag_clear, char **err)
{
	struct buffer *retptr;

	FLT_OT_FUNC("%hhu, %p:%p", flag_clear, FLT_OT_DPTR_ARGS(err));

#ifdef USE_TRASH_CHUNK
	retptr = alloc_trash_chunk();
	if (retptr != NULL)
		FLT_OT_DBG(2, "TRASH_ALLOC: %s:%d(%p %zu)", __func__, __LINE__, retptr, retptr->size);
#else
	retptr = FLT_OT_MALLOC(sizeof(*retptr));
	if (retptr != NULL) {
		chunk_init(retptr, FLT_OT_MALLOC(global.tune.bufsize), global.tune.bufsize);
		if (retptr->area == NULL)
			FLT_OT_FREE_CLEAR(retptr);
		else
			*(retptr->area) = '\0';
	}
#endif

	if (retptr == NULL)
		FLT_OT_ERR("out of memory");
	else if (flag_clear)
		(void)memset(retptr->area, 0, retptr->size);

	FLT_OT_RETURN(retptr);
}


/***
 * NAME
 *   flt_ot_trash_free -
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
void flt_ot_trash_free(struct buffer **ptr)
{
	FLT_OT_FUNC("%p:%p", FLT_OT_DPTR_ARGS(ptr));

	if ((ptr == NULL) || (*ptr == NULL))
		FLT_OT_RETURN();

	FLT_OT_DBG(2, "TRASH_FREE: %s:%d(%p %zu)", __func__, __LINE__, *ptr, (*ptr)->size);

#ifdef USE_TRASH_CHUNK
	free_trash_chunk(*ptr);
#else
	FLT_OT_FREE((*ptr)->area);
	FLT_OT_FREE(*ptr);
#endif

	*ptr = NULL;

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
