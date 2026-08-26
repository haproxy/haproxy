#ifndef _HAPROXY_HALOAD_H
#define _HAPROXY_HALOAD_H

#include <import/ist.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/task-t.h>

#define HLD_HAS_HTTP_VER_0   (1U << HLD_HTTP_VER_0)
#define HLD_HAS_HTTP_VER_1   (1U << HLD_HTTP_VER_1)
#define HLD_HAS_HTTP_VER_2   (1U << HLD_HTTP_VER_2)
#define HLD_HAS_HTTP_VER_3   (1U << HLD_HTTP_VER_3)

enum hld_http_ver {
	HLD_HTTP_VER_0,
	HLD_HTTP_VER_1,
	HLD_HTTP_VER_2,
	HLD_HTTP_VER_3,
	/* Do not add more enum below */
	HLD_HTTP_VER_MAX,
};


struct hld_path {
	char *path;
	enum http_meth_t http_meth;
	struct ist meth_ist;
	int post_sz;
	struct hld_path *next;
};

struct hld_url_cfg {
	int ssl;
	int is_quic;
	int h2c;
	int thnk_time;
	enum hld_http_ver http_ver;
	char *addr;
	char *raw_addr; // used only to set the host header value
	char *srv_opts;
	char *tls_opts;
	char *alpn;
	struct server *srv;
	struct hld_path *paths;
	struct hld_path *cur_path;
	struct hld_url_cfg *next;
};

struct hld_url {
	int mreqs;
	uint64_t tot_req;
	uint64_t tot_rconn_done;
	uint64_t tot_rconn_sent;
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
extern int arg_accu;
extern int arg_dura;
extern int arg_fast;
extern int arg_hscd;
extern int arg_long;
extern int arg_mreqs;
extern int arg_pctl;
extern int arg_post_sz;
extern int arg_rate;
extern int arg_reqs;
extern int arg_rcon;
extern int arg_slow;
extern int arg_serr;
extern int arg_usr;
extern int arg_thnk;
extern int arg_thrd;
extern int arg_wait;

extern unsigned int hld_ver_flags;
#endif /* _HAPROXY_HALOAD_H */
