/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_HTTP_H_
#define _OTEL_HTTP_H_

#ifndef DEBUG_OTEL
#  define flt_otel_http_headers_dump(...)   while (0)
#else
/* Dump all HTTP headers from a channel for debugging. */
void                   flt_otel_http_headers_dump(const struct channel *chn);
#endif

/* Extract HTTP headers matching a prefix into a text map. */
struct otelc_text_map *flt_otel_http_headers_get(struct channel *chn, const char *prefix, size_t len, char **err);

/* Set or replace an HTTP header in a channel. */
int                    flt_otel_http_header_set(struct channel *chn, const char *prefix, const char *name, const char *value, char **err);

/* Remove all HTTP headers matching a prefix from a channel. */
int                    flt_otel_http_headers_remove(struct channel *chn, const char *prefix, char **err);

#endif /* _OTEL_HTTP_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
