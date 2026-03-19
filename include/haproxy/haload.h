#ifndef _HAPROXY_HALOAD_H
#define _HAPROXY_HALOAD_H

#include <import/ist.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/task-t.h>

struct hld_path {
	const char *path;
	struct hld_path *next;
};

struct hld_url_cfg {
	int ssl;
	const char *addr;
	const char *raw_addr;
	char *ssl_opts;
	struct server *srv;
	struct hld_path *paths;
	struct hld_url_cfg *next;
};

struct hld_url {
	int nreqs;
	int mreqs;
	int flags;
	int conns;
	struct hld_url_cfg *cfg;
	struct hld_url *next;
};

/* haload header */
struct hld_hdr {
	struct ist name;
	struct ist value;
	struct list list;
};

extern const char *arg_host;
extern const char *arg_conn_hdr;
extern const char *arg_uri;
extern const char *arg_path; // TO REMOVE
extern struct list hld_hdrs;
extern struct hld_url_cfg *hld_url_cfgs;

extern struct proxy hld_proxy;
extern int arg_dura; // test duration (-d)
extern int arg_long; // long output (-l)
extern int arg_reqs; // total number of reqs (-n)
extern int arg_mreqs; // total number of reqs in flight by connection (-m)
extern int arg_rcon; // number of reqs by connection (-r)
extern int arg_usr;  // number of users (-u)
extern int arg_wait; // timeout
extern int arg_head; // HEAD request (-I)
extern int arg_hscd; // HTTP status distribution (-S)

#endif /* _HAPROXY_HALOAD_H */
