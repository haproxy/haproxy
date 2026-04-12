/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_DEFINE_H_
#define _OTEL_DEFINE_H_

/* Check whether argument at index n is in range, non-NULL and non-empty. */
#define FLT_OTEL_ARG_ISVALID(n)      ({ typeof(n) _n = (n); OTELC_IN_RANGE(_n, 0, MAX_LINE_ARGS - 1) && (args[_n] != NULL) && (*args[_n] != '\0'); })

/* Convert a floating-point percentage to a uint32_t rate value. */
#define FLT_OTEL_FLOAT_U32(a)        ((uint32_t)((a) / 100.0 * UINT32_MAX + 0.5))

/* Compile-time string length excluding the null terminator. */
#define FLT_OTEL_STR_SIZE(a)         (sizeof(a) - 1)

/* Execute a statement exactly once across all invocations. */
#define FLT_OTEL_RUN_ONCE(f)         do { static bool _f = 1; if (_f) { _f = 0; { f; } } } while (0)

/* Check whether a list head has been initialized. */
#define FLT_OTEL_LIST_ISVALID(a)     ({ typeof(a) _a = (a); (_a != NULL) && (_a->n != NULL) && (_a->p != NULL); })

/* Safely delete a list element if its list head is valid. */
#define FLT_OTEL_LIST_DEL(a)         do { if (FLT_OTEL_LIST_ISVALID(a)) LIST_DELETE(a); } while (0)

/* Destroy all elements in a typed configuration list. */
#define FLT_OTEL_LIST_DESTROY(t,h)                                                     \
	do {                                                                           \
		struct flt_otel_conf_##t *_ptr, *_back;                                \
		                                                                       \
		if (!FLT_OTEL_LIST_ISVALID(h) || LIST_ISEMPTY(h))                      \
			break;                                                         \
		                                                                       \
		OTELC_DBG(NOTICE, "- deleting " #t " list %s", flt_otel_list_dump(h)); \
		                                                                       \
		list_for_each_entry_safe(_ptr, _back, (h), list)                       \
			flt_otel_conf_##t##_free(&_ptr);                               \
	} while (0)

/* Declare a rotating thread-local string buffer pool. */
#define FLT_OTEL_BUFFER_THR(b,m,n,p)              \
	static THREAD_LOCAL char    b[m][n];      \
	static THREAD_LOCAL size_t  __idx = 0;    \
	char                       *p = b[__idx]; \
	__idx = (__idx + 1) % (m)

/* Format an error message if none has been set yet. */
#define FLT_OTEL_ERR(f, ...)                                    \
	do {                                                    \
		if ((err != NULL) && (*err == NULL)) {          \
			(void)memprintf(err, f, ##__VA_ARGS__); \
		                                                \
			OTELC_DBG(DEBUG, "err: '%s'", *err);    \
		}                                               \
	} while (0)
/* Append to an existing error message unconditionally. */
#define FLT_OTEL_ERR_APPEND(f, ...)                             \
	do {                                                    \
		if (err != NULL)                                \
			(void)memprintf(err, f, ##__VA_ARGS__); \
	} while (0)
/* Log an error message and free its memory. */
#define FLT_OTEL_ERR_FREE(p)                                                 \
	do {                                                                 \
		if ((p) == NULL)                                             \
			break;                                               \
		                                                             \
		OTELC_DBG(LOG, "%s:%d: ERROR: %s", __func__, __LINE__, (p)); \
		OTELC_SFREE_CLEAR(p);                                        \
	} while (0)

#endif /* _OTEL_DEFINE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
