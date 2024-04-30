#ifndef _HAPROXY_STATS_FILE_H
#define _HAPROXY_STATS_FILE_H

#include <haproxy/stats-file-t.h>

#include <sys/types.h>

#include <haproxy/buf-t.h>
#include <haproxy/stats-t.h>

int stats_dump_fields_file(struct buffer *out,
                           const struct field *stats, size_t stats_count,
                           struct show_stat_ctx *ctx);

void stats_dump_file_header(int type, struct buffer *out);

/* Maximum number of parsed stat column in a header line.
 * Directly based on ST_I_PX_MAX, with value doubled to obtain compatibility
 * between haproxy adjacent versions.
 */
#define STAT_FILE_MAX_COL_COUNT    (ST_I_PX_MAX*2)

void apply_stats_file(void);

#endif /* _HAPROXY_STATS_FILE_H */
