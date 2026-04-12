/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_POOL_H_
#define _OTEL_POOL_H_

#define FLT_OTEL_POOL_INIT(p,n,s,r)                                                       \
	do {                                                                              \
		if (((r) == FLT_OTEL_RET_OK) && ((p) == NULL)) {                          \
			(p) = create_pool(n, (s), MEM_F_SHARED);                          \
			if ((p) == NULL)                                                  \
				(r) = FLT_OTEL_RET_ERROR;                                 \
			                                                                  \
			OTELC_DBG(DEBUG, #p " %p %u", (p), FLT_OTEL_DEREF((p), size, 0)); \
		}                                                                         \
	} while (0)

#define FLT_OTEL_POOL_DESTROY(p)                                       \
	do {                                                           \
		if ((p) != NULL) {                                     \
			OTELC_DBG(DEBUG, #p " %p %u", (p), (p)->size); \
			                                               \
			pool_destroy(p);                               \
			(p) = NULL;                                    \
		}                                                      \
	} while (0)


extern struct pool_head *pool_head_otel_scope_span __read_mostly;
extern struct pool_head *pool_head_otel_scope_context __read_mostly;
extern struct pool_head *pool_head_otel_runtime_context __read_mostly;
extern struct pool_head *pool_head_otel_span_context __read_mostly;


/* Allocate memory from a pool with optional zeroing. */
void          *flt_otel_pool_alloc(struct pool_head *pool, size_t size, bool flag_clear, char **err);

/* Duplicate a string into pool-allocated memory. */
void          *flt_otel_pool_strndup(struct pool_head *pool, const char *s, size_t size, char **err);

/* Release pool-allocated memory and clear the pointer. */
void           flt_otel_pool_free(struct pool_head *pool, void **ptr);

/* Initialize OTel filter memory pools. */
int            flt_otel_pool_init(void);

/* Destroy OTel filter memory pools. */
void           flt_otel_pool_destroy(void);

/* Log debug information about OTel filter memory pools. */
#ifndef DEBUG_OTEL
#  define flt_otel_pool_info()   while (0)
#else
void           flt_otel_pool_info(void);
#endif

/* Allocate a trash buffer with optional zeroing. */
struct buffer *flt_otel_trash_alloc(bool flag_clear, char **err);

/* Release a trash buffer and clear the pointer. */
void           flt_otel_trash_free(struct buffer **ptr);

#endif /* _OTEL_POOL_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
