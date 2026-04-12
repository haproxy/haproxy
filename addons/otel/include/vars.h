/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_VARS_H_
#define _OTEL_VARS_H_

#define FLT_OTEL_VARS_SCOPE       "txn"
#define FLT_OTEL_VAR_CTX_SIZE     int8_t
#define FLT_OTEL_VAR_CHAR_DASH    'D'
#define FLT_OTEL_VAR_CHAR_SPACE   'S'

/* Context buffer for storing a single variable value during iteration. */
struct flt_otel_ctx {
	char value[BUFSIZ]; /* Variable value string. */
	int  value_len;     /* Length of the value string. */
};

/* Callback type invoked for each context variable during iteration. */
typedef int (*flt_otel_ctx_loop_cb)(struct sample *, size_t, const char *, const char *, const char *, FLT_OTEL_VAR_CTX_SIZE, char **, void *);


#ifndef DEBUG_OTEL
#  define flt_otel_vars_dump(...)   while (0)
#else
/* Dump all OTel-related variables for a stream. */
void                   flt_otel_vars_dump(struct stream *s);
#endif

/* Register a HAProxy variable for OTel context storage. */
int                    flt_otel_var_register(const char *scope, const char *prefix, const char *name, char **err);

/* Set an OTel context variable on a stream. */
int                    flt_otel_var_set(struct stream *s, const char *scope, const char *prefix, const char *name, const char *value, uint opt, char **err);

/* Unset all OTel context variables matching a prefix on a stream. */
int                    flt_otel_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err);

/* Retrieve all OTel context variables matching a prefix into a text map. */
struct otelc_text_map *flt_otel_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err);

#endif /* _OTEL_VARS_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
