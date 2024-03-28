#ifndef _HAPROXY_STATS_FILE_H
#define _HAPROXY_STATS_FILE_H

#include <sys/types.h>

#include <haproxy/buf-t.h>
#include <haproxy/stats-t.h>

int stats_dump_fields_file(struct buffer *out,
                           const struct field *stats, size_t stats_count,
                           struct show_stat_ctx *ctx);

void stats_dump_file_header(int type, struct buffer *out);

#endif /* _HAPROXY_STATS_FILE_H */
