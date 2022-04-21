#ifndef _HAPROXY_INIT_T_H
#define _HAPROXY_INIT_T_H

#include <haproxy/list-t.h>

struct proxy;
struct server;

struct pre_check_fct {
	struct list list;
	int (*fct)();
};

struct post_check_fct {
	struct list list;
	int (*fct)();
};

struct post_proxy_check_fct {
	struct list list;
	int (*fct)(struct proxy *);
};

struct post_server_check_fct {
	struct list list;
	int (*fct)(struct server *);
};

struct per_thread_alloc_fct {
	struct list list;
	int (*fct)();
};

struct per_thread_init_fct {
	struct list list;
	int (*fct)();
};

struct post_deinit_fct {
	struct list list;
	void (*fct)();
};

struct proxy_deinit_fct {
	struct list list;
	void (*fct)(struct proxy *);
};

struct server_deinit_fct {
	struct list list;
	void (*fct)(struct server *);
};

struct per_thread_free_fct {
	struct list list;
	void (*fct)();
};

struct per_thread_deinit_fct {
	struct list list;
	void (*fct)();
};

#endif /* _HAPROXY_INIT_T_H */
