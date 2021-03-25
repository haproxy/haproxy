#ifndef _HAPROXY_INIT_H
#define _HAPROXY_INIT_H

#include <haproxy/init-t.h>
#include <haproxy/initcall.h>

struct proxy;
struct server;

extern struct list post_check_list;
extern struct list post_proxy_check_list;
extern struct list post_server_check_list;
extern struct list per_thread_alloc_list;
extern struct list per_thread_init_list;
extern struct list post_deinit_list;
extern struct list proxy_deinit_list;
extern struct list server_deinit_list;
extern struct list per_thread_free_list;
extern struct list per_thread_deinit_list;

void hap_register_post_check(int (*fct)());
void hap_register_post_proxy_check(int (*fct)(struct proxy *));
void hap_register_post_server_check(int (*fct)(struct server *));
void hap_register_post_deinit(void (*fct)());
void hap_register_proxy_deinit(void (*fct)(struct proxy *));
void hap_register_server_deinit(void (*fct)(struct server *));

void hap_register_per_thread_alloc(int (*fct)());
void hap_register_per_thread_init(int (*fct)());
void hap_register_per_thread_deinit(void (*fct)());
void hap_register_per_thread_free(void (*fct)());

/* simplified way to declare a post-check callback in a file */
#define REGISTER_POST_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_check, (fct))

/* simplified way to declare a post-proxy-check callback in a file */
#define REGISTER_POST_PROXY_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_proxy_check, (fct))

/* simplified way to declare a post-server-check callback in a file */
#define REGISTER_POST_SERVER_CHECK(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_server_check, (fct))

/* simplified way to declare a post-deinit callback in a file */
#define REGISTER_POST_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_post_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_PROXY_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_proxy_deinit, (fct))

/* simplified way to declare a proxy-deinit callback in a file */
#define REGISTER_SERVER_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_server_deinit, (fct))

/* simplified way to declare a per-thread allocation callback in a file */
#define REGISTER_PER_THREAD_ALLOC(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_alloc, (fct))

/* simplified way to declare a per-thread init callback in a file */
#define REGISTER_PER_THREAD_INIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_init, (fct))

/* simplified way to declare a per-thread deinit callback in a file */
#define REGISTER_PER_THREAD_DEINIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_deinit, (fct))

/* simplified way to declare a per-thread free callback in a file */
#define REGISTER_PER_THREAD_FREE(fct) \
	INITCALL1(STG_REGISTER, hap_register_per_thread_free, (fct))

#endif /* _HAPROXY_INIT_H */
