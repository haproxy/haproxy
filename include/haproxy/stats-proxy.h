#ifndef _HAPROXY_STATS_PROXY_H
#define _HAPROXY_STATS_PROXY_H

struct buffer;
struct htx;
struct stconn;

int stats_dump_proxies(struct stconn *sc, struct buffer *buf, struct htx *htx);

#endif /* _HAPROXY_STATS_PROXY_H */
