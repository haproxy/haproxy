#ifndef _HAPROXY_STATS_PROXY_H
#define _HAPROXY_STATS_PROXY_H

#include <haproxy/api-t.h>

struct buffer;
struct htx;
struct stconn;
struct uri_auth;
struct proxy;

int stats_dump_proxies(struct stconn *sc, struct buffer *buf, struct htx *htx);

void proxy_stats_clear_counters(int clrall, struct list *stat_modules);
int stats_proxy_in_scope(const struct proxy *px, const struct uri_auth *uri,
                         const struct proxy *http_px);

#endif /* _HAPROXY_STATS_PROXY_H */
