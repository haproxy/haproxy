#ifndef _HAPROXY_STATS_JSON_H
#define _HAPROXY_STATS_JSON_H

#include <haproxy/applet-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/stats-t.h>

void stats_dump_json_header(struct buffer *out);

int stats_dump_fields_json(struct buffer *out,
                           const struct field *stats, size_t stats_count,
                           struct show_stat_ctx *ctx);

void stats_dump_json_end(struct buffer *out);

int stats_dump_json_info_fields(struct buffer *out,
                                const struct field *info,
                                struct show_stat_ctx *ctx);

void stats_dump_json_schema(struct buffer *out);

int stats_dump_json_schema_to_buffer(struct appctx *appctx);

#endif /* _HAPROXY_STATS_JSON_H */
