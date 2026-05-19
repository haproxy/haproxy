#ifndef _HAPROXY_HALOAD_H
#define _HAPROXY_HALOAD_H

#include <import/ist.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/task-t.h>

struct hld_path {
	char *path;
	struct hld_path *next;
};

struct hld_url_cfg {
	int ssl;
	char *addr;
	char *raw_addr; // used only to set the host header value
	char *srv_opts;
	char *tls_opts;
	struct server *srv;
	struct hld_path *paths;
	struct hld_url_cfg *next;
};

struct hld_url {
	int mreqs;
	int flags;
	uint64_t tot_req;
	uint64_t tot_done;
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
extern int arg_dura;
extern int arg_head;
extern int arg_hscd;
extern int arg_long;
extern int arg_mreqs;
extern int arg_reqs;
extern int arg_rcon;
extern int arg_slow;
extern int arg_usr;
extern int arg_nbthrds;
extern int arg_wait;

#endif /* _HAPROXY_HALOAD_H */
