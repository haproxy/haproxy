#ifndef _HAPROXY_STATS_HTML_H
#define _HAPROXY_STATS_HTML_H

#include <haproxy/stats-html-t.h>

#include <haproxy/applet-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn-t.h>

void stats_dump_html_head(struct appctx *appctx);
void stats_dump_html_info(struct stconn *sc);
int stats_dump_fields_html(struct buffer *out, const struct field *stats,
                           struct show_stat_ctx *ctx);
void stats_dump_html_px_hdr(struct stconn *sc, struct proxy *px);
void stats_dump_html_px_end(struct stconn *sc, struct proxy *px);
void stats_dump_html_end(struct buffer *out);

extern struct applet http_stats_applet;

#endif /* _HAPROXY_STATS_HTML_H */
