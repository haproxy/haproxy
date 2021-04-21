#include <stdio.h>
#include <stdlib.h>

#include <haproxy/init.h>
#include <haproxy/list.h>

/* These functions are called just after the point where the program exits
 * after a config validity check, so they are generally suited for resource
 * allocation and slow initializations that should be skipped during basic
 * config checks. The functions must return 0 on success, or a combination
 * of ERR_* flags (ERR_WARN, ERR_ABORT, ERR_FATAL, ...). The 2 latter cause
 * and immediate exit, so the function must have emitted any useful error.
 */
struct list post_check_list = LIST_HEAD_INIT(post_check_list);

/* These functions are called for each proxy just after the config validity
 * check. The functions must return 0 on success, or a combination of ERR_*
 * flags (ERR_WARN, ERR_ABORT, ERR_FATAL, ...). The 2 latter cause and immediate
 * exit, so the function must have emitted any useful error.
 */
struct list post_proxy_check_list = LIST_HEAD_INIT(post_proxy_check_list);

/* These functions are called for each server just after the config validity
 * check. The functions must return 0 on success, or a combination of ERR_*
 * flags (ERR_WARN, ERR_ABORT, ERR_FATAL, ...). The 2 latter cause and immediate
 * exit, so the function must have emitted any useful error.
 */
struct list post_server_check_list = LIST_HEAD_INIT(post_server_check_list);

/* These functions are called for each thread just after the thread creation
 * and before running the init functions. They should be used to do per-thread
 * (re-)allocations that are needed by subsequent functoins. They must return 0
 * if an error occurred. */
struct list per_thread_alloc_list = LIST_HEAD_INIT(per_thread_alloc_list);

/* These functions are called for each thread just after the thread creation
 * and before running the scheduler. They should be used to do per-thread
 * initializations. They must return 0 if an error occurred. */
struct list per_thread_init_list = LIST_HEAD_INIT(per_thread_init_list);

/* These functions are called when freeing the global sections at the end of
 * deinit, after everything is stopped. They don't return anything. They should
 * not release shared resources that are possibly used by other deinit
 * functions, only close/release what is private. Use the per_thread_free_list
 * to release shared resources.
 */
struct list post_deinit_list = LIST_HEAD_INIT(post_deinit_list);

/* These functions are called when freeing a proxy during the deinit, after
 * everything isg stopped. They don't return anything. They should not release
 * the proxy itself or any shared resources that are possibly used by other
 * deinit functions, only close/release what is private.
 */
struct list proxy_deinit_list = LIST_HEAD_INIT(proxy_deinit_list);

/* These functions are called when freeing a server during the deinit, after
 * everything isg stopped. They don't return anything. They should not release
 * the proxy itself or any shared resources that are possibly used by other
 * deinit functions, only close/release what is private.
 */
struct list server_deinit_list = LIST_HEAD_INIT(server_deinit_list);

/* These functions are called when freeing the global sections at the end of
 * deinit, after the thread deinit functions, to release unneeded memory
 * allocations. They don't return anything, and they work in best effort mode
 * as their sole goal is to make valgrind mostly happy.
 */
struct list per_thread_free_list = LIST_HEAD_INIT(per_thread_free_list);

/* These functions are called for each thread just after the scheduler loop and
 * before exiting the thread. They don't return anything and, as for post-deinit
 * functions, they work in best effort mode as their sole goal is to make
 * valgrind mostly happy. */
struct list per_thread_deinit_list = LIST_HEAD_INIT(per_thread_deinit_list);

/* used to register some initialization functions to call after the checks. */
void hap_register_post_check(int (*fct)())
{
	struct post_check_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&post_check_list, &b->list);
}

/* used to register some initialization functions to call for each proxy after
 * the checks.
 */
void hap_register_post_proxy_check(int (*fct)(struct proxy *))
{
	struct post_proxy_check_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&post_proxy_check_list, &b->list);
}

/* used to register some initialization functions to call for each server after
 * the checks.
 */
void hap_register_post_server_check(int (*fct)(struct server *))
{
	struct post_server_check_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&post_server_check_list, &b->list);
}

/* used to register some de-initialization functions to call after everything
 * has stopped.
 */
void hap_register_post_deinit(void (*fct)())
{
	struct post_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&post_deinit_list, &b->list);
}

/* used to register some per proxy de-initialization functions to call after
 * everything has stopped.
 */
void hap_register_proxy_deinit(void (*fct)(struct proxy *))
{
	struct proxy_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&proxy_deinit_list, &b->list);
}

/* used to register some per server de-initialization functions to call after
 * everything has stopped.
 */
void hap_register_server_deinit(void (*fct)(struct server *))
{
	struct server_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&server_deinit_list, &b->list);
}

/* used to register some allocation functions to call for each thread. */
void hap_register_per_thread_alloc(int (*fct)())
{
	struct per_thread_alloc_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&per_thread_alloc_list, &b->list);
}

/* used to register some initialization functions to call for each thread. */
void hap_register_per_thread_init(int (*fct)())
{
	struct per_thread_init_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&per_thread_init_list, &b->list);
}

/* used to register some de-initialization functions to call for each thread. */
void hap_register_per_thread_deinit(void (*fct)())
{
	struct per_thread_deinit_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&per_thread_deinit_list, &b->list);
}

/* used to register some free functions to call for each thread. */
void hap_register_per_thread_free(void (*fct)())
{
	struct per_thread_free_fct *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->fct = fct;
	LIST_APPEND(&per_thread_free_list, &b->list);
}
