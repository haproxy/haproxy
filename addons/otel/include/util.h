/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_UTIL_H_
#define _OTEL_UTIL_H_

#define FLT_OTEL_HTTP_METH_DEFINES      \
	FLT_OTEL_HTTP_METH_DEF(OPTIONS) \
	FLT_OTEL_HTTP_METH_DEF(GET)     \
	FLT_OTEL_HTTP_METH_DEF(HEAD)    \
	FLT_OTEL_HTTP_METH_DEF(POST)    \
	FLT_OTEL_HTTP_METH_DEF(PUT)     \
	FLT_OTEL_HTTP_METH_DEF(DELETE)  \
	FLT_OTEL_HTTP_METH_DEF(TRACE)   \
	FLT_OTEL_HTTP_METH_DEF(CONNECT)

#ifdef DEBUG_OTEL
#  define FLT_OTEL_ARGS_DUMP()   do { if (otelc_dbg_level & (1 << OTELC_DBG_LEVEL_LOG)) flt_otel_args_dump((const char **)args); } while (0)
#else
#  define FLT_OTEL_ARGS_DUMP()   while (0)
#endif


#ifdef DEBUG_OTEL
/* Dump configuration arguments for debugging. */
void        flt_otel_args_dump(const char **args);

/* Dump a linked list of configuration items as a string. */
const char *flt_otel_list_dump(const struct list *head);
#endif

/* Count the number of non-NULL arguments in an argument array. */
int         flt_otel_args_count(const char **args);

/* Concatenate argument array elements into a single string. */
int         flt_otel_args_concat(const char **args, int idx, int n, char **str);

/* Parse a string to double with range validation. */
bool        flt_otel_strtod(const char *nptr, double *value, double limit_min, double limit_max, char **err);

/* Parse a string to int64_t with range validation. */
bool        flt_otel_strtoll(const char *nptr, int64_t *value, int64_t limit_min, int64_t limit_max, char **err);

/* Convert sample data to a string representation. */
int         flt_otel_sample_to_str(const struct sample_data *data, char *value, size_t size, char **err);

#endif /* _OTEL_UTIL_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
