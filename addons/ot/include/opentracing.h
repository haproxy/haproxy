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
#ifndef _OPENTRACING_OT_H_
#define _OPENTRACING_OT_H_

#include <opentracing-c-wrapper/include.h>


#define FLT_OT_VSET(p,t,v) \
	do { (p)->type = otc_value_##t; (p)->value.t##_value = (v); } while (0)

#define FLT_OT_DBG_TEXT_MAP(a)                     \
	FLT_OT_DBG(3, "%p:{ %p %p %zu/%zu %hhu }", \
	           (a), (a)->key, (a)->value, (a)->count, (a)->size, (a)->is_dynamic)

#define FLT_OT_DBG_TEXT_CARRIER(a,f)                                                 \
	FLT_OT_DBG(3, "%p:{ { %p %p %zu/%zu %hhu } %p }",                            \
	           (a), (a)->text_map.key, (a)->text_map.value, (a)->text_map.count, \
	           (a)->text_map.size, (a)->text_map.is_dynamic, (a)->f)

#define FLT_OT_DBG_CUSTOM_CARRIER(a,f)                                \
	FLT_OT_DBG(3, "%p:{ { %p %zu %hhu } %p }",                    \
	           (a), (a)->binary_data.data, (a)->binary_data.size, \
	           (a)->binary_data.is_dynamic, (a)->f)

#define FLT_OT_DBG_SPAN_CONTEXT(a) \
	FLT_OT_DBG(3, "%p:{ %" PRId64 " %p %p }", (a), (a)->idx, (a)->span, (a)->destroy)


#ifndef DEBUG_OT
#  define ot_debug()              while (0)
#  define ot_text_map_show(...)   while (0)
#else
void                     ot_text_map_show(const struct otc_text_map *text_map);
void                     ot_debug(void);
#endif
int                      ot_init(struct otc_tracer **tracer, const char *config, const char *plugin, char **err);
struct otc_span         *ot_span_init(struct otc_tracer *tracer, const char *operation_name, const struct timespec *ts_steady, const struct timespec *ts_system, int ref_type, int ref_ctx_idx, const struct otc_span *ref_span, const struct otc_tag *tags, int num_tags, char **err);
int                      ot_span_tag(struct otc_span *span, const struct otc_tag *tags, int num_tags);
int                      ot_span_log(struct otc_span *span, const struct otc_log_field *log_fields, int num_fields);
int                      ot_span_set_baggage(struct otc_span *span, const struct otc_text_map *baggage);
struct otc_span_context *ot_inject_http_headers(struct otc_tracer *tracer, const struct otc_span *span, struct otc_http_headers_writer *carrier, char **err);
struct otc_span_context *ot_extract_http_headers(struct otc_tracer *tracer, struct otc_http_headers_reader *carrier, const struct otc_text_map *text_map, char **err);
void                     ot_span_finish(struct otc_span **span, const struct timespec *ts_finish, const struct timespec *log_ts, const char *log_key, const char *log_value, ...);
void                     ot_close(struct otc_tracer **tracer);

/* Unused code. */
struct otc_span         *ot_span_init_va(struct otc_tracer *tracer, const char *operation_name, const struct timespec *ts_steady, const struct timespec *ts_system, int ref_type, int ref_ctx_idx, const struct otc_span *ref_span, char **err, const char *tag_key, const char *tag_value, ...);
int                      ot_span_tag_va(struct otc_span *span, const char *key, int type, ...);
int                      ot_span_log_va(struct otc_span *span, const char *key, const char *value, ...);
int                      ot_span_log_fmt(struct otc_span *span, const char *key, const char *format, ...) __attribute__ ((format(printf, 3, 4)));
int                      ot_span_set_baggage_va(struct otc_span *span, const char *key, const char *value, ...);
struct otc_text_map     *ot_span_baggage_va(const struct otc_span *span, const char *key, ...);
struct otc_span_context *ot_inject_text_map(struct otc_tracer *tracer, const struct otc_span *span, struct otc_text_map_writer *carrier);
struct otc_span_context *ot_inject_binary(struct otc_tracer *tracer, const struct otc_span *span, struct otc_custom_carrier_writer *carrier);
struct otc_span_context *ot_extract_text_map(struct otc_tracer *tracer, struct otc_text_map_reader *carrier, const struct otc_text_map *text_map);
struct otc_span_context *ot_extract_binary(struct otc_tracer *tracer, struct otc_custom_carrier_reader *carrier, const struct otc_binary_data *binary_data);

#endif /* _OPENTRACING_OT_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
