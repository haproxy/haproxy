/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_OTELC_H_
#define _OTEL_OTELC_H_

/* Inject span context into a text map carrier. */
int                        flt_otel_inject_text_map(const struct otelc_span *span, struct otelc_text_map_writer *carrier);

/* Inject span context into an HTTP headers carrier. */
int                        flt_otel_inject_http_headers(const struct otelc_span *span, struct otelc_http_headers_writer *carrier);

/* Extract span context from a text map carrier. */
struct otelc_span_context *flt_otel_extract_text_map(struct otelc_tracer *tracer, struct otelc_text_map_reader *carrier, const struct otelc_text_map *text_map);

/* Extract span context from an HTTP headers carrier. */
struct otelc_span_context *flt_otel_extract_http_headers(struct otelc_tracer *tracer, struct otelc_http_headers_reader *carrier, const struct otelc_text_map *text_map);

#endif /* _OTEL_OTELC_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
