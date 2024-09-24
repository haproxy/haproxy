/*
 * Lua unsafe core engine
 *
 * Copyright 2015-2016 Thierry Fournier <tfournier@arpalert.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <setjmp.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
#error "Requires Lua 5.3 or later."
#endif

#include <import/ebpttree.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/arg.h>
#include <haproxy/auth.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/connection.h>
#include <haproxy/filters.h>
#include <haproxy/h1.h>
#include <haproxy/hlua.h>
#include <haproxy/hlua_fcn.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_client.h>
#include <haproxy/http_fetch.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/map.h>
#include <haproxy/obj_type.h>
#include <haproxy/pattern.h>
#include <haproxy/payload.h>
#include <haproxy/proxy.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>
#include <haproxy/xref.h>
#include <haproxy/event_hdl.h>
#include <haproxy/check.h>
#include <haproxy/mailers.h>

/* Global LUA flags */

enum hlua_log_opt {
	/* tune.lua.log.loggers */
	HLUA_LOG_LOGGERS_ON      = 0x00000001, /* forward logs to current loggers */

	/* tune.lua.log.stderr */
	HLUA_LOG_STDERR_ON       = 0x00000010, /* forward logs to stderr */
	HLUA_LOG_STDERR_AUTO     = 0x00000020, /* forward logs to stderr if no loggers */
	HLUA_LOG_STDERR_MASK     = 0x00000030,
};
/* default log options, made of flags in hlua_log_opt */
static uint hlua_log_opts = HLUA_LOG_LOGGERS_ON | HLUA_LOG_STDERR_AUTO;

/* Lua uses longjmp to perform yield or throwing errors. This
 * macro is used only for identifying the function that can
 * not return because a longjmp is executed.
 *   __LJMP marks a prototype of hlua file that can use longjmp.
 *   WILL_LJMP() marks an lua function that will use longjmp.
 *   MAY_LJMP() marks an lua function that may use longjmp.
 */
#define __LJMP
#define WILL_LJMP(func) do { func; my_unreachable(); } while(0)
#define MAY_LJMP(func) func

/* This couple of function executes securely some Lua calls outside of
 * the lua runtime environment. Each Lua call can return a longjmp
 * if it encounter a memory error.
 *
 * Lua documentation extract:
 *
 *   If an error happens outside any protected environment, Lua calls
 *   a panic function (see lua_atpanic) and then calls abort, thus
 *   exiting the host application. Your panic function can avoid this
 *   exit by never returning (e.g., doing a long jump to your own
 *   recovery point outside Lua).
 *
 *   The panic function runs as if it were a message handler (see
 *   #2.3); in particular, the error message is at the top of the
 *   stack. However, there is no guarantee about stack space. To push
 *   anything on the stack, the panic function must first check the
 *   available space (see #4.2).
 *
 * We must check all the Lua entry point. This includes:
 *  - The include/proto/hlua.h exported functions
 *  - the task wrapper function
 *  - The action wrapper function
 *  - The converters wrapper function
 *  - The sample-fetch wrapper functions
 *
 * It is tolerated that the initialisation function returns an abort.
 * Before each Lua abort, an error message is written on stderr.
 *
 * The macro SET_SAFE_LJMP initialise the longjmp. The Macro
 * RESET_SAFE_LJMP reset the longjmp. These function must be macro
 * because they must be exists in the program stack when the longjmp
 * is called.
 *
 * Note that the Lua processing is not really thread safe. It provides
 * heavy system which consists to add our own lock function in the Lua
 * code and recompile the library. This system will probably not accepted
 * by maintainers of various distribs.
 *
 * Our main execution point of the Lua is the function lua_resume(). A
 * quick looking on the Lua sources displays a lua_lock() a the start
 * of function and a lua_unlock() at the end of the function. So I
 * conclude that the Lua thread safe mode just perform a mutex around
 * all execution. So I prefer to do this in the HAProxy code, it will be
 * easier for distro maintainers.
 *
 * Note that the HAProxy lua functions rounded by the macro SET_SAFE_LJMP
 * and RESET_SAFE_LJMP manipulates the Lua stack, so it will be careful
 * to set mutex around these functions.
 */
__decl_spinlock(hlua_global_lock);
THREAD_LOCAL jmp_buf safe_ljmp_env;
static int hlua_panic_safe(lua_State *L) { return 0; }
static int hlua_panic_ljmp(lua_State *L) { WILL_LJMP(longjmp(safe_ljmp_env, 1)); return 0; }

/* This is the chained list of struct hlua_function referenced
 * for haproxy action, sample-fetches, converters, cli and
 * applet bindings. It is used for a post-initialisation control.
 */
static struct list referenced_functions = LIST_HEAD_INIT(referenced_functions);

/* This variable is used only during initialization to identify the Lua state
 * currently being initialized. 0 is the common lua state, 1 to n are the Lua
 * states dedicated to each thread (in this case hlua_state_id==tid+1).
 */
static int hlua_state_id;

/* This is a NULL-terminated list of lua file which are referenced to load per thread */
static char ***per_thread_load = NULL;

lua_State *hlua_init_state(int thread_id);

/* This function takes the Lua global lock. Keep this function's visibility
 * global so that it can appear in stack dumps and performance profiles!
 */
static inline void lua_take_global_lock()
{
	HA_SPIN_LOCK(LUA_LOCK, &hlua_global_lock);
}

static inline void lua_drop_global_lock()
{
	HA_SPIN_UNLOCK(LUA_LOCK, &hlua_global_lock);
}

/* lua lock helpers: only lock when required
 *
 * state_id == 0: we're operating on the main lua stack (shared between
 * os threads), so we need to acquire the main lock
 *
 * If the thread already owns the lock (_hlua_locked != 0), skip the lock
 * attempt. This could happen if we run under protected lua environment.
 * Not doing this could result in deadlocks because of nested locking
 * attempts from the same thread
 */
static THREAD_LOCAL int _hlua_locked = 0;
static inline void hlua_lock(struct hlua *hlua)
{
	if (hlua->state_id != 0)
		return;
	if (!_hlua_locked)
		lua_take_global_lock();
	_hlua_locked += 1;
}
static inline void hlua_unlock(struct hlua *hlua)
{
	if (hlua->state_id != 0)
		return;
	BUG_ON(_hlua_locked <= 0);
	_hlua_locked--;
	/* drop the lock once the lock count reaches 0 */
	if (!_hlua_locked)
		lua_drop_global_lock();
}

/* below is an helper function to retrieve string on on Lua stack at <index>
 * in a safe way (function may not LJMP). It can be useful to retrieve errors
 * at the top of the stack from an unprotected environment.
 *
 * The returned string will is only valid as long as the value at <index> is
 * not removed from the stack.
 *
 * It is assumed that the calling function is allowed to manipulate <L>
 */
__LJMP static int _hlua_tostring_safe(lua_State *L)
{
	const char **str = lua_touserdata(L, 1);
	const char *cur_str = MAY_LJMP(lua_tostring(L, 2));

	if (cur_str)
		*str = cur_str;
	return 0;
}
static const char *hlua_tostring_safe(lua_State *L, int index)
{
	const char *str = NULL;

	if (!lua_checkstack(L, 4))
		return NULL;

	/* before any stack modification, save the targeted value on the top of
	 * the stack: this will allow us to use relative index to target it.
	 */
	lua_pushvalue(L, index);

	/* push our custom _hlua_tostring_safe() function on the stack, then push
	 * our own string pointer and targeted value (at <index>) as argument
	 */
	lua_pushcfunction(L, _hlua_tostring_safe);
	lua_pushlightuserdata(L, &str); // 1st func argument = string pointer
	lua_pushvalue(L, -3);           // 2nd func argument = targeted value

	lua_remove(L, -4); // remove <index> copy as we're done using it

	/* call our custom function with proper arguments using pcall() to catch
	 * exceptions (if any)
	 */
	switch (lua_pcall(L, 2, 0, 0)) {
		case LUA_OK:
			break;
		default:
			/* error was caught */
			return NULL;
	}
	return str;
}

/* below is an helper function similar to lua_pushvfstring() to push a
 * formatted string on Lua stack but in a safe way (function may not LJMP).
 * It can be useful to push allocated strings (ie: error messages) on the
 * stack and ensure proper cleanup.
 *
 * Returns a pointer to the internal copy of the string on success and NULL
 * on error.
 *
 * It is assumed that the calling function is allowed to manipulate <L>
 */
__LJMP static int _hlua_pushvfstring_safe(lua_State *L)
{
	const char **dst = lua_touserdata(L, 1);
	const char *fmt = lua_touserdata(L, 2);
	va_list *argp = lua_touserdata(L, 3);

	*dst = lua_pushvfstring(L, fmt, *argp);
	return 1;
}
static const char *hlua_pushvfstring_safe(lua_State *L, const char *fmt, va_list argp)
{
	const char *dst = NULL;
	va_list cpy_argp; /* required if argp is implemented as array type */

	if (!lua_checkstack(L, 4))
		return NULL;

	va_copy(cpy_argp, argp);

	/* push our custom _hlua_pushvfstring_safe() function on the stack, then
	 * push our destination string pointer, fmt and arg list
	 */
	lua_pushcfunction(L, _hlua_pushvfstring_safe);
	lua_pushlightuserdata(L, &dst);        // 1st func argument = dst string pointer
	lua_pushlightuserdata(L, (void *)fmt); // 2nd func argument = fmt
	lua_pushlightuserdata(L, &cpy_argp);   // 3rd func argument = arg list

	/* call our custom function with proper arguments using pcall() to catch
	 * exceptions (if any)
	 */
	switch (lua_pcall(L, 3, 1, 0)) {
		case LUA_OK:
			break;
		default:
			/* error was caught */
			dst = NULL;
	}
	va_end(cpy_argp);

	return dst;
}

static const char *hlua_pushfstring_safe(lua_State *L, const char *fmt, ...)
{
	va_list argp;
	const char *dst;

	va_start(argp, fmt);
	dst = hlua_pushvfstring_safe(L, fmt, argp);
	va_end(argp);

	return dst;
}

#define SET_SAFE_LJMP_L(__L, __HLUA) \
	({ \
		int ret; \
		hlua_lock(__HLUA); \
		if (setjmp(safe_ljmp_env) != 0) { \
			lua_atpanic(__L, hlua_panic_safe); \
			ret = 0; \
			hlua_unlock(__HLUA); \
		} else { \
			lua_atpanic(__L, hlua_panic_ljmp); \
			ret = 1; \
		} \
		ret; \
	})

/* If we are the last function catching Lua errors, we
 * must reset the panic function.
 */
#define RESET_SAFE_LJMP_L(__L, __HLUA) \
	do { \
		lua_atpanic(__L, hlua_panic_safe); \
		hlua_unlock(__HLUA); \
	} while(0)

#define SET_SAFE_LJMP(__HLUA) \
	SET_SAFE_LJMP_L((__HLUA)->T, __HLUA)

#define RESET_SAFE_LJMP(__HLUA) \
	RESET_SAFE_LJMP_L((__HLUA)->T, __HLUA)

#define SET_SAFE_LJMP_PARENT(__HLUA) \
	SET_SAFE_LJMP_L(hlua_states[(__HLUA)->state_id], __HLUA)

#define RESET_SAFE_LJMP_PARENT(__HLUA) \
	RESET_SAFE_LJMP_L(hlua_states[(__HLUA)->state_id], __HLUA)

/* Applet status flags */
#define APPLET_DONE     0x01 /* applet processing is done. */
/* unused: 0x02 */
#define APPLET_HDR_SENT 0x04 /* Response header sent. */
/* unused: 0x08, 0x10 */
#define APPLET_HTTP11   0x20 /* Last chunk sent. */
#define APPLET_RSP_SENT 0x40 /* The response was fully sent */

/* The main Lua execution context. The 0 index is the
 * common state shared by all threads.
 */
static lua_State *hlua_states[MAX_THREADS + 1];

#define HLUA_FLT_CB_FINAL         0x00000001
#define HLUA_FLT_CB_RETVAL        0x00000002
#define HLUA_FLT_CB_ARG_CHN       0x00000004
#define HLUA_FLT_CB_ARG_HTTP_MSG  0x00000008

#define HLUA_FLT_CTX_FL_PAYLOAD  0x00000001

struct hlua_reg_filter  {
	char *name;
	int flt_ref[MAX_THREADS + 1];
	int fun_ref[MAX_THREADS + 1];
	struct list l;
};

struct hlua_flt_config {
	struct hlua_reg_filter *reg;
	int ref[MAX_THREADS + 1];
	char **args;
};

struct hlua_flt_ctx {
	struct hlua *_hlua;      /* main hlua context */
	int ref;                 /* ref to the filter lua object (in main hlua context) */
	struct hlua *hlua[2];    /* lua runtime context (0: request, 1: response) */
	unsigned int cur_off[2]; /* current offset (0: request, 1: response) */
	unsigned int cur_len[2]; /* current forwardable length (0: request, 1: response) */
	unsigned int flags;      /* HLUA_FLT_CTX_FL_* */
};

/* appctx context used by the cosockets */
struct hlua_csk_ctx {
	int connected;
	struct xref xref; /* cross reference with the Lua object owner. */
	struct list wake_on_read;
	struct list wake_on_write;
	struct appctx *appctx;
	struct server *srv;
	int timeout;
	int die;
};

/* appctx context used by TCP services */
struct hlua_tcp_ctx {
	struct hlua *hlua;
	int flags;
	struct task *task;
};

/* appctx context used by HTTP services */
struct hlua_http_ctx {
	struct hlua *hlua;
	int left_bytes;         /* The max amount of bytes that we can read. */
	int flags;
	int status;
	const char *reason;
	struct task *task;
};

/* used by registered CLI keywords */
struct hlua_cli_ctx {
	struct hlua *hlua;
	struct task *task;
	struct hlua_function *fcn;
};

DECLARE_STATIC_POOL(pool_head_hlua_flt_ctx, "hlua_flt_ctx", sizeof(struct hlua_flt_ctx));

static int hlua_filter_from_payload(struct filter *filter);

/* This is the chained list of struct hlua_flt referenced
 * for haproxy filters. It is used for a post-initialisation control.
 */
static struct list referenced_filters = LIST_HEAD_INIT(referenced_filters);


/* This is the memory pool containing struct lua for applets
 * (including cli).
 */
DECLARE_STATIC_POOL(pool_head_hlua, "hlua", sizeof(struct hlua));

/* Used for Socket connection. */
static struct proxy *socket_proxy;
static struct server *socket_tcp;
#ifdef USE_OPENSSL
static struct server *socket_ssl;
#endif

/* List head of the function called at the initialisation time. */
struct list hlua_init_functions[MAX_THREADS + 1];

/* The following variables contains the reference of the different
 * Lua classes. These references are useful for identify metadata
 * associated with an object.
 */
static int class_txn_ref;
static int class_socket_ref;
static int class_channel_ref;
static int class_fetches_ref;
static int class_converters_ref;
static int class_http_ref;
static int class_http_msg_ref;
static int class_httpclient_ref;
static int class_map_ref;
static int class_applet_tcp_ref;
static int class_applet_http_ref;
static int class_txn_reply_ref;

/* Lua max execution timeouts. By default, stream-related
 * lua coroutines (e.g.: actions) have a short timeout.
 * On the other hand tasks coroutines don't have a timeout because
 * a task may remain alive during all the haproxy execution.
 *
 * Timeouts are expressed in milliseconds, they are meant to be used
 * with hlua timer's API exclusively.
 * 0 means no timeout
 */
static uint32_t hlua_timeout_burst = 1000; /* burst timeout. */
static uint32_t hlua_timeout_session = 4000; /* session timeout. */
static uint32_t hlua_timeout_task = 0; /* task timeout. */
static uint32_t hlua_timeout_applet = 4000; /* applet timeout. */

/* hlua multipurpose timer:
 *  used to compute burst lua time (within a single hlua_ctx_resume())
 *  and cumulative lua time for a given coroutine, and to check
 *  the lua coroutine against the configured timeouts
 */

/* fetch per-thread cpu_time with ms precision (may wrap) */
static inline uint32_t _hlua_time_ms()
{
	/* We're interested in the current cpu time in ms, which will be returned
	 * as a uint32_t to save some space.
	 * We must take the following into account:
	 *
	 * - now_cpu_time_fast() which returns the time in nanoseconds as a uint64_t
	 *   will wrap every 585 years.
	 * - uint32_t may only contain 4294967295ms (~=49.7 days), so _hlua_time_ms()
	 *   itself will also wrap every 49.7 days.
	 *
	 * While we can safely ignore the now_cpu_time_fast() wrap, we must
	 * take care of the uint32_t wrap by making sure to exclusively
	 * manipulate the time using uint32_t everywhere _hlua_time_ms()
	 * is involved.
	 */
	return (uint32_t)(now_cpu_time_fast() / 1000000ULL);
}

/* computes time spent in a single lua execution (in ms) */
static inline uint32_t _hlua_time_burst(const struct hlua_timer *timer)
{
	uint32_t burst_ms;

	/* wrapping is expected and properly
	 * handled thanks to _hlua_time_ms() and burst_ms
	 * being of the same type
	 */
	burst_ms = _hlua_time_ms() - timer->start;
	return burst_ms;
}

static inline void hlua_timer_init(struct hlua_timer *timer, unsigned int max)
{
	timer->cumulative = 0;
	timer->burst = 0;
	timer->max = max;
}

/* reset the timer ctx between 2 yields */
static inline void hlua_timer_reset(struct hlua_timer *timer)
{
	timer->cumulative += timer->burst;
	timer->burst = 0;
}

/* start the timer right before a new execution */
static inline void hlua_timer_start(struct hlua_timer *timer)
{
	timer->start = _hlua_time_ms();
}

/* update hlua timer when finishing an execution */
static inline void hlua_timer_stop(struct hlua_timer *timer)
{
	timer->burst += _hlua_time_burst(timer);
}

/* check the timers for current hlua context:
 * - first check for burst timeout (max execution time for the current
     hlua resume, ie: time between effective yields)
 * - then check for yield cumulative timeout
 *
 * Returns 1 if the check succeeded, 0 if it failed because cumulative
 * timeout is exceeded, and -1 if it failed because burst timeout is
 * exceeded.
 */
static inline int hlua_timer_check(const struct hlua_timer *timer)
{
	uint32_t pburst = _hlua_time_burst(timer); /* pending burst time in ms */

	if (hlua_timeout_burst && (timer->burst + pburst) > hlua_timeout_burst)
		return -1; /* burst timeout exceeded */
	if (timer->max && (timer->cumulative + timer->burst + pburst) > timer->max)
		return 0; /* cumulative timeout exceeded */
	return 1; /* ok */
}

/* Interrupts the Lua processing each "hlua_nb_instruction" instructions.
 * it is used for preventing infinite loops.
 */
static unsigned int hlua_nb_instruction = 0;

/* Wrapper to retrieve the number of instructions between two interrupts
 * depending on user settings and current hlua context. If not already
 * explicitly set, we compute the ideal value using hard limits releaved
 * by Thierry Fournier's work, whose original notes may be found below:
 *
 * --
 * I test the scheer with an infinite loop containing one incrementation
 * and one test. I run this loop between 10 seconds, I raise a ceil of
 * 710M loops from one interrupt each 9000 instructions, so I fix the value
 * to one interrupt each 10 000 instructions.
 *
 *  configured    | Number of
 *  instructions  | loops executed
 *  between two   | in milions
 *  forced yields |
 * ---------------+---------------
 *  10            | 160
 *  500           | 670
 *  1000          | 680
 *  5000          | 700
 *  7000          | 700
 *  8000          | 700
 *  9000          | 710 <- ceil
 *  10000         | 710
 *  100000        | 710
 *  1000000       | 710
 * --
 *
 * Thanks to his work, we know we can safely use values between 500 and 10000
 * without a significant impact on performance.
 */
static inline unsigned int hlua_get_nb_instruction(struct hlua *hlua)
{
	int ceil = 10000; /* above 10k, no significant performance gain */
	int floor = 500;  /* below 500, significant performance loss */

	if (hlua_nb_instruction) {
		/* value enforced by user */
		return hlua_nb_instruction;
	}

	/* not set, assign automatic value */
	if (hlua->state_id == 0) {
		/* this function is expected to be called during runtime (after config
		 * parsing), thus global.nb_thread is expected to be set.
		 */
		BUG_ON(global.nbthread == 0);

		/* main lua stack (shared global lock), take number of threads into
		 * account in an attempt to reduce thread contention
		 */
		return MAX(floor, ceil / global.nbthread);
	}
	else {
		/* per-thread lua stack, less contention is expected (no global lock),
		 * allow up to the maximum number of instructions and hope that the
		 * user manually yields after heavy (lock dependent) work from lua
		 * script (e.g.: map manipulation).
		 */
		return ceil;
	}
}

/* Descriptor for the memory allocation state. The limit is pre-initialised to
 * 0 until it is replaced by "tune.lua.maxmem" during the config parsing, or it
 * is replaced with ~0 during post_init after everything was loaded. This way
 * it is guaranteed that if limit is ~0 the boot is complete and that if it's
 * zero it's not yet limited and proper accounting is required.
 */
struct hlua_mem_allocator {
	size_t allocated;
	size_t limit;
};

static struct hlua_mem_allocator hlua_global_allocator THREAD_ALIGNED(64);

/* hlua event subscription */
struct hlua_event_sub {
	int fcn_ref;
	int state_id;
	struct hlua *hlua;
	struct task *task;
	event_hdl_async_equeue equeue;
	struct event_hdl_sub *sub;
	uint8_t paused;
};

/* This is the memory pool containing struct hlua_event_sub
 * for event subscriptions from lua
 */
DECLARE_STATIC_POOL(pool_head_hlua_event_sub, "hlua_esub", sizeof(struct hlua_event_sub));

/* These functions converts types between HAProxy internal args or
 * sample and LUA types. Another function permits to check if the
 * LUA stack contains arguments according with an required ARG_T
 * format.
 */
__LJMP static int hlua_arg2lua(lua_State *L, const struct arg *arg);
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg);
__LJMP static int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                                     uint64_t mask, struct proxy *p);
__LJMP static int hlua_smp2lua(lua_State *L, struct sample *smp);
__LJMP static int hlua_smp2lua_str(lua_State *L, struct sample *smp);
static int hlua_lua2smp(lua_State *L, int ud, struct sample *smp);

__LJMP static int hlua_http_get_headers(lua_State *L, struct http_msg *msg);

struct prepend_path {
	struct list l;
	char *type;
	char *path;
};

static struct list prepend_path_list = LIST_HEAD_INIT(prepend_path_list);

#define SEND_ERR(__be, __fmt, __args...) \
	do { \
		send_log(__be, LOG_ERR, __fmt, ## __args); \
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) \
			ha_alert(__fmt, ## __args); \
	} while (0)

static inline struct hlua_function *new_hlua_function()
{
	struct hlua_function *fcn;
	int i;

	fcn = calloc(1, sizeof(*fcn));
	if (!fcn)
		return NULL;
	LIST_APPEND(&referenced_functions, &fcn->l);
	for (i = 0; i < MAX_THREADS + 1; i++)
		fcn->function_ref[i] = -1;
	return fcn;
}

static inline void release_hlua_function(struct hlua_function *fcn)
{
	if (!fcn)
		return;
	if (fcn->name)
		ha_free(&fcn->name);
	LIST_DELETE(&fcn->l);
	ha_free(&fcn);
}

/* If the common state is set, the stack id is 0, otherwise it is the tid + 1 */
static inline int fcn_ref_to_stack_id(struct hlua_function *fcn)
{
	if (fcn->function_ref[0] == -1)
		return tid + 1;
	return 0;
}

/* Create a new registered filter. Only its name is filled */
static inline struct hlua_reg_filter *new_hlua_reg_filter(const char *name)
{
	struct hlua_reg_filter *reg_flt;
	int i;

	reg_flt = calloc(1, sizeof(*reg_flt));
	if (!reg_flt)
		return NULL;
	reg_flt->name = strdup(name);
	if (!reg_flt->name) {
		free(reg_flt);
		return NULL;
	}
	LIST_APPEND(&referenced_filters, &reg_flt->l);
	for (i = 0; i < MAX_THREADS + 1; i++) {
		reg_flt->flt_ref[i] = -1;
		reg_flt->fun_ref[i] = -1;
	}
	return reg_flt;
}

/* Release a registered filter */
static inline void release_hlua_reg_filter(struct hlua_reg_filter *reg_flt)
{
	if (!reg_flt)
		return;
	if (reg_flt->name)
		ha_free(&reg_flt->name);
	LIST_DELETE(&reg_flt->l);
	ha_free(&reg_flt);
}

/* If the common state is set, the stack id is 0, otherwise it is the tid + 1 */
static inline int reg_flt_to_stack_id(struct hlua_reg_filter *reg_flt)
{
	if (reg_flt->fun_ref[0] == -1)
		return tid + 1;
	return 0;
}

/* Used to check an Lua function type in the stack. It creates and
 * returns a reference of the function. This function throws an
 * error if the argument is not a "function".
 * When no longer used, the ref must be released with hlua_unref()
 */
__LJMP int hlua_checkfunction(lua_State *L, int argno)
{
	if (!lua_isfunction(L, argno)) {
		const char *msg = lua_pushfstring(L, "function expected, got %s", luaL_typename(L, argno));
		WILL_LJMP(luaL_argerror(L, argno, msg));
	}
	lua_pushvalue(L, argno);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* Used to check an Lua table type in the stack. It creates and
 * returns a reference of the table. This function throws an
 * error if the argument is not a "table".
 * When no longer used, the ref must be released with hlua_unref()
 */
__LJMP int hlua_checktable(lua_State *L, int argno)
{
	if (!lua_istable(L, argno)) {
		const char *msg = lua_pushfstring(L, "table expected, got %s", luaL_typename(L, argno));
		WILL_LJMP(luaL_argerror(L, argno, msg));
	}
	lua_pushvalue(L, argno);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* Get a reference to the object that is at the top of the stack
 * The referenced object will be popped from the stack
 *
 * The function returns the reference to the object which must
 * be cleared using hlua_unref() when no longer used
 */
__LJMP int hlua_ref(lua_State *L)
{
	return MAY_LJMP(luaL_ref(L, LUA_REGISTRYINDEX));
}

/* Pushes a reference previously created using luaL_ref(L, LUA_REGISTRYINDEX)
 * on <L> stack
 * (ie: hlua_checkfunction(), hlua_checktable() or hlua_ref())
 *
 * When the reference is no longer used, it should be released by calling
 * hlua_unref()
 *
 * <L> can be from any co-routine as long as it belongs to the same lua
 * parent state that the one used to get the reference.
 */
void hlua_pushref(lua_State *L, int ref)
{
	lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
}

/* Releases a reference previously created using luaL_ref(L, LUA_REGISTRYINDEX)
 * (ie: hlua_checkfunction(), hlua_checktable() or hlua_ref())
 *
 * This will allow the reference to be reused and the referred object
 * to be garbage collected.
 *
 * <L> can be from any co-routine as long as it belongs to the same lua
 * parent state that the one used to get the reference.
 */
void hlua_unref(lua_State *L, int ref)
{
	luaL_unref(L, LUA_REGISTRYINDEX, ref);
}

__LJMP static int _hlua_traceback(lua_State *L)
{
	lua_Debug *ar = lua_touserdata(L, 1);

	/* Fill fields:
	 * 'S': fills in the fields source, short_src, linedefined, lastlinedefined, and what;
	 * 'l': fills in the field currentline;
	 * 'n': fills in the field name and namewhat;
	 * 't': fills in the field istailcall;
	 */
	return lua_getinfo(L, "Slnt", ar);
}


/* This function cannot fail (output will simply be truncated upon errors) */
const char *hlua_traceback(lua_State *L, const char* sep)
{
	lua_Debug ar;
	int level = 0;
	struct buffer *msg = get_trash_chunk();

	while (lua_getstack(L, level++, &ar)) {
		if (!lua_checkstack(L, 2))
			goto end; // abort

		lua_pushcfunction(L, _hlua_traceback);
		lua_pushlightuserdata(L, &ar);

		/* safe getinfo */
		switch (lua_pcall(L, 1, 1, 0)) {
			case LUA_OK:
				break;
			default:
				goto end; // abort
		}

		/* skip these empty entries, usually they come from deep C functions */
		if (ar.currentline < 0 && *ar.what == 'C' && !*ar.namewhat && !ar.name)
			continue;

		/* Add separator */
		if (b_data(msg))
			chunk_appendf(msg, "%s", sep);

		/* Append code localisation */
		if (ar.currentline > 0)
			chunk_appendf(msg, "%s:%d: ", ar.short_src, ar.currentline);
		else
			chunk_appendf(msg, "%s: ", ar.short_src);

		/*
		 * Get function name
		 *
		 * if namewhat is no empty, name is defined.
		 * what contains "Lua" for Lua function, "C" for C function,
		 * or "main" for main code.
		 */
		if (*ar.namewhat != '\0' && ar.name != NULL)  /* is there a name from code? */
			chunk_appendf(msg, "in %s '%s'", ar.namewhat, ar.name);  /* use it */

		else if (*ar.what == 'm')  /* "main", the code is not executed in a function */
			chunk_appendf(msg, "in main chunk");

		else if (*ar.what != 'C')  /* for Lua functions, use <file:line> */
			chunk_appendf(msg, "in function line %d", ar.linedefined);

		else  /* nothing left... */
			chunk_appendf(msg, "?");


		/* Display tailed call */
		if (ar.istailcall)
			chunk_appendf(msg, " ...");
	}

 end:
	return msg->area;
}


/* This function check the number of arguments available in the
 * stack. If the number of arguments available is not the same
 * then <nb> an error is thrown.
 */
__LJMP static inline void check_args(lua_State *L, int nb, char *fcn)
{
	if (lua_gettop(L) == nb)
		return;
	WILL_LJMP(luaL_error(L, "'%s' needs %d arguments", fcn, nb));
}

/* This function pushes an error string prefixed by the file name
 * and the line number where the error is encountered.
 *
 * It returns 1 on success and 0 on failure (function won't LJMP)
 */
__LJMP static int _hlua_pusherror(lua_State *L)
{
	const char *fmt = lua_touserdata(L, 1);
	va_list *argp = lua_touserdata(L, 2);

	luaL_where(L, 2);
	lua_pushvfstring(L, fmt, *argp);
	lua_concat(L, 2);

	return 1;
}
static int hlua_pusherror(lua_State *L, const char *fmt, ...)
{
	va_list argp;
	int ret = 1;

	if (!lua_checkstack(L, 3))
		return 0;

	va_start(argp, fmt);

	/* push our custom _hlua_pusherror() function on the stack, then
	 * push fmt and arg list
	 */
	lua_pushcfunction(L, _hlua_pusherror);
	lua_pushlightuserdata(L, (void *)fmt); // 1st func argument = fmt
	lua_pushlightuserdata(L, &argp);       // 2nd func argument = arg list

	/* call our custom function with proper arguments using pcall() to catch
	 * exceptions (if any)
	 */
	switch (lua_pcall(L, 2, 1, 0)) {
		case LUA_OK:
			break;
		default:
			ret = 0;
	}

	va_end(argp);

	return ret;
}

/* This functions is used with sample fetch and converters. It
 * converts the HAProxy configuration argument in a lua stack
 * values.
 *
 * It takes an array of "arg", and each entry of the array is
 * converted and pushed in the LUA stack.
 */
__LJMP static int hlua_arg2lua(lua_State *L, const struct arg *arg)
{
	switch (arg->type) {
	case ARGT_SINT:
	case ARGT_TIME:
	case ARGT_SIZE:
		lua_pushinteger(L, arg->data.sint);
		break;

	case ARGT_STR:
		lua_pushlstring(L, arg->data.str.area, arg->data.str.data);
		break;

	case ARGT_IPV4:
	case ARGT_IPV6:
	case ARGT_MSK4:
	case ARGT_MSK6:
	case ARGT_FE:
	case ARGT_BE:
	case ARGT_TAB:
	case ARGT_SRV:
	case ARGT_USR:
	case ARGT_MAP:
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

/* This function take one entry in an LUA stack at the index "ud",
 * and try to convert it in an HAProxy argument entry. This is useful
 * with sample fetch wrappers. The input arguments are given to the
 * lua wrapper and converted as arg list by the function.
 *
 * Note: although lua_tolstring() may raise a memory error according to
 * lua documentation, in practise this could only happen when using to
 * use lua_tolstring() on a number (lua will try to push the number as a
 * string on the stack, and this may result in memory failure), so here we
 * assume that hlua_lua2arg() will never raise an exception since it is
 * exclusively used with lua string inputs.
 *
 * Note2: You should be extra careful when using <arg> argument, since
 * string arguments rely on lua_tolstring() which returns a pointer to lua
 * object that may be garbage collected at any time when removed from lua
 * stack, thus you should make sure that <arg> is only used from a local
 * scope within lua context (and not exported or stored in a lua-independent
 * ctx) and that related lua object still exists when accessing arg data.
 * See: https://www.lua.org/manual/5.4/manual.html#4.1.3
 */
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg)
{
	switch (lua_type(L, ud)) {

	case LUA_TNUMBER:
	case LUA_TBOOLEAN:
		arg->type = ARGT_SINT;
		arg->data.sint = lua_tointeger(L, ud);
		break;

	case LUA_TSTRING:
		arg->type = ARGT_STR;
		arg->data.str.area = (char *)lua_tolstring(L, ud, &arg->data.str.data);
		/* We don't know the actual size of the underlying allocation, so be conservative. */
		arg->data.str.size = arg->data.str.data+1; /* count the terminating null byte */
		arg->data.str.head = 0;
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
		arg->type = ARGT_SINT;
		arg->data.sint = 0;
		break;
	}
	return 1;
}

/* the following functions are used to convert a struct sample
 * in Lua type. This useful to convert the return of the
 * fetches or converters.
 */
__LJMP static int hlua_smp2lua(lua_State *L, struct sample *smp)
{
	switch (smp->data.type) {
	case SMP_T_SINT:
	case SMP_T_BOOL:
		lua_pushinteger(L, smp->data.u.sint);
		break;

	case SMP_T_BIN:
	case SMP_T_STR:
		lua_pushlstring(L, smp->data.u.str.area, smp->data.u.str.data);
		break;

	case SMP_T_METH:
		switch (smp->data.u.meth.meth) {
		case HTTP_METH_OPTIONS: lua_pushstring(L, "OPTIONS"); break;
		case HTTP_METH_GET:     lua_pushstring(L, "GET");     break;
		case HTTP_METH_HEAD:    lua_pushstring(L, "HEAD");    break;
		case HTTP_METH_POST:    lua_pushstring(L, "POST");    break;
		case HTTP_METH_PUT:     lua_pushstring(L, "PUT");     break;
		case HTTP_METH_DELETE:  lua_pushstring(L, "DELETE");  break;
		case HTTP_METH_TRACE:   lua_pushstring(L, "TRACE");   break;
		case HTTP_METH_CONNECT: lua_pushstring(L, "CONNECT"); break;
		case HTTP_METH_OTHER:
			lua_pushlstring(L, smp->data.u.meth.str.area, smp->data.u.meth.str.data);
			break;
		default:
			lua_pushnil(L);
			break;
		}
		break;

	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_ADDR: /* This type is never used to qualify a sample. */
		if (sample_casts[smp->data.type][SMP_T_STR] &&
		    sample_casts[smp->data.type][SMP_T_STR](smp))
			lua_pushlstring(L, smp->data.u.str.area, smp->data.u.str.data);
		else
			lua_pushnil(L);
		break;
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

/* the following functions are used to convert a struct sample
 * in Lua strings. This is useful to convert the return of the
 * fetches or converters.
 */
__LJMP static int hlua_smp2lua_str(lua_State *L, struct sample *smp)
{
	switch (smp->data.type) {

	case SMP_T_BIN:
	case SMP_T_STR:
		lua_pushlstring(L, smp->data.u.str.area, smp->data.u.str.data);
		break;

	case SMP_T_METH:
		switch (smp->data.u.meth.meth) {
		case HTTP_METH_OPTIONS: lua_pushstring(L, "OPTIONS"); break;
		case HTTP_METH_GET:     lua_pushstring(L, "GET");     break;
		case HTTP_METH_HEAD:    lua_pushstring(L, "HEAD");    break;
		case HTTP_METH_POST:    lua_pushstring(L, "POST");    break;
		case HTTP_METH_PUT:     lua_pushstring(L, "PUT");     break;
		case HTTP_METH_DELETE:  lua_pushstring(L, "DELETE");  break;
		case HTTP_METH_TRACE:   lua_pushstring(L, "TRACE");   break;
		case HTTP_METH_CONNECT: lua_pushstring(L, "CONNECT"); break;
		case HTTP_METH_OTHER:
			lua_pushlstring(L, smp->data.u.meth.str.area, smp->data.u.meth.str.data);
			break;
		default:
			lua_pushstring(L, "");
			break;
		}
		break;

	case SMP_T_SINT:
	case SMP_T_BOOL:
	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_ADDR: /* This type is never used to qualify a sample. */
		if (sample_casts[smp->data.type][SMP_T_STR] &&
		    sample_casts[smp->data.type][SMP_T_STR](smp))
			lua_pushlstring(L, smp->data.u.str.area, smp->data.u.str.data);
		else
			lua_pushstring(L, "");
		break;
	default:
		lua_pushstring(L, "");
		break;
	}
	return 1;
}

/* The following function is used to convert a Lua type to a
 * struct sample. This is useful to provide data from LUA code to
 * a converter.
 *
 * Note: although lua_tolstring() may raise a memory error according to
 * lua documentation, in practise this could only happen when using to
 * use lua_tolstring() on a number (lua will try to push the number as a
 * string on the stack, and this may result in memory failure), so here we
 * assume that hlua_lua2arg() will never raise an exception since it is
 * exclusively used with lua string inputs.
 *
 * Note2: You should be extra careful when using <smp> argument, since
 * string arguments rely on lua_tolstring() which returns a pointer to lua
 * object that may be garbage collected at any time when removed from lua
 * stack, thus you should make sure that <smp> is only used from a local
 * scope within lua context (not exported or stored in a lua-independent
 * ctx) and that related lua object still exists when accessing arg data.
 * See: https://www.lua.org/manual/5.4/manual.html#4.1.3
 *
 * If you don't comply with this usage restriction, then you should consider
 * duplicating the smp using smp_dup() to make it portable (little overhead),
 * as this will ensure that the smp always points to valid memory block.
 */
static int hlua_lua2smp(lua_State *L, int ud, struct sample *smp)
{
	switch (lua_type(L, ud)) {

	case LUA_TNUMBER:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = lua_tointeger(L, ud);
		break;


	case LUA_TBOOLEAN:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = lua_toboolean(L, ud);
		break;

	case LUA_TSTRING:
		smp->data.type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->data.u.str.area = (char *)lua_tolstring(L, ud, &smp->data.u.str.data);
		/* We don't know the actual size of the underlying allocation, so be conservative. */
		smp->data.u.str.size = smp->data.u.str.data+1; /* count the terminating null byte */
		smp->data.u.str.head = 0;
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
	case LUA_TNONE:
	default:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = 0;
		break;
	}
	return 1;
}

/* This function check the "argp" built by another conversion function
 * is in accord with the expected argp defined by the "mask". The function
 * returns true or false. It can be adjust the types if there compatibles.
 *
 * This function assumes that the argp argument contains ARGM_NBARGS + 1
 * entries and that there is at least one stop at the last position.
 */
__LJMP int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                              uint64_t mask, struct proxy *p)
{
	int min_arg;
	int idx;
	struct proxy *px;
	struct userlist *ul;
	struct my_regex *reg;
	const char *msg = NULL;
	char *sname, *pname, *err = NULL;

	idx = 0;
	min_arg = ARGM(mask);
	mask >>= ARGM_BITS;

	while (1) {
		struct buffer tmp = BUF_NULL;

		/* Check for mandatory arguments. */
		if (argp[idx].type == ARGT_STOP) {
			if (idx < min_arg) {

				/* If miss other argument than the first one, we return an error. */
				if (idx > 0) {
					msg = "Mandatory argument expected";
					goto error;
				}

				/* If first argument have a certain type, some default values
				 * may be used. See the function smp_resolve_args().
				 */
				switch (mask & ARGT_MASK) {

				case ARGT_FE:
					if (!(p->cap & PR_CAP_FE)) {
						msg = "Mandatory argument expected";
						goto error;
					}
					argp[idx].data.prx = p;
					argp[idx].type = ARGT_FE;
					argp[idx+1].type = ARGT_STOP;
					break;

				case ARGT_BE:
					if (!(p->cap & PR_CAP_BE)) {
						msg = "Mandatory argument expected";
						goto error;
					}
					argp[idx].data.prx = p;
					argp[idx].type = ARGT_BE;
					argp[idx+1].type = ARGT_STOP;
					break;

				case ARGT_TAB:
					if (!p->table) {
						msg = "Mandatory argument expected";
						goto error;
					}
					argp[idx].data.t = p->table;
					argp[idx].type = ARGT_TAB;
					argp[idx+1].type = ARGT_STOP;
					break;

				default:
					msg = "Mandatory argument expected";
					goto error;
					break;
				}
			}
			break;
		}

		/* Check for exceed the number of required argument. */
		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type != ARGT_STOP) {
			msg = "Last argument expected";
			goto error;
		}

		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type == ARGT_STOP) {
			break;
		}

		/* Convert some argument types. All string in argp[] are for not
		 * duplicated yet.
		 */
		switch (mask & ARGT_MASK) {
		case ARGT_SINT:
			if (argp[idx].type != ARGT_SINT) {
				msg = "integer expected";
				goto error;
			}
			argp[idx].type = ARGT_SINT;
			break;

		case ARGT_TIME:
			if (argp[idx].type != ARGT_SINT) {
				msg = "integer expected";
				goto error;
			}
			argp[idx].type = ARGT_TIME;
			break;

		case ARGT_SIZE:
			if (argp[idx].type != ARGT_SINT) {
				msg = "integer expected";
				goto error;
			}
			argp[idx].type = ARGT_SIZE;
			break;

		case ARGT_FE:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			argp[idx].data.prx = proxy_fe_by_name(argp[idx].data.str.area);
			if (!argp[idx].data.prx) {
				msg = "frontend doesn't exist";
				goto error;
			}
			argp[idx].type = ARGT_FE;
			break;

		case ARGT_BE:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			argp[idx].data.prx = proxy_be_by_name(argp[idx].data.str.area);
			if (!argp[idx].data.prx) {
				msg = "backend doesn't exist";
				goto error;
			}
			argp[idx].type = ARGT_BE;
			break;

		case ARGT_TAB:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			argp[idx].data.t = stktable_find_by_name(argp[idx].data.str.area);
			if (!argp[idx].data.t) {
				msg = "table doesn't exist";
				goto error;
			}
			argp[idx].type = ARGT_TAB;
			break;

		case ARGT_SRV:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			sname = strrchr(argp[idx].data.str.area, '/');
			if (sname) {
				*sname++ = '\0';
				pname = argp[idx].data.str.area;
				px = proxy_be_by_name(pname);
				if (!px) {
					msg = "backend doesn't exist";
					goto error;
				}
			}
			else {
				sname = argp[idx].data.str.area;
				px = p;
			}
			argp[idx].data.srv = findserver(px, sname);
			if (!argp[idx].data.srv) {
				msg = "server doesn't exist";
				goto error;
			}
			argp[idx].type = ARGT_SRV;
			break;

		case ARGT_IPV4:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			if (inet_pton(AF_INET, argp[idx].data.str.area, &argp[idx].data.ipv4)) {
				msg = "invalid IPv4 address";
				goto error;
			}
			argp[idx].type = ARGT_IPV4;
			break;

		case ARGT_MSK4:
			if (argp[idx].type == ARGT_SINT)
				len2mask4(argp[idx].data.sint, &argp[idx].data.ipv4);
			else if (argp[idx].type == ARGT_STR) {
				if (!str2mask(argp[idx].data.str.area, &argp[idx].data.ipv4)) {
					msg = "invalid IPv4 mask";
					goto error;
				}
			}
			else  {
				msg = "integer or string expected";
				goto error;
			}
			argp[idx].type = ARGT_MSK4;
			break;

		case ARGT_IPV6:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			if (inet_pton(AF_INET6, argp[idx].data.str.area, &argp[idx].data.ipv6)) {
				msg = "invalid IPv6 address";
				goto error;
			}
			argp[idx].type = ARGT_IPV6;
			break;

		case ARGT_MSK6:
			if (argp[idx].type == ARGT_SINT)
				len2mask6(argp[idx].data.sint, &argp[idx].data.ipv6);
			else if (argp[idx].type == ARGT_STR) {
				if (!str2mask6(argp[idx].data.str.area, &argp[idx].data.ipv6)) {
					msg = "invalid IPv6 mask";
					goto error;
				}
			}
			else {
				msg = "integer or string expected";
				goto error;
			}
			argp[idx].type = ARGT_MSK6;
			break;

		case ARGT_REG:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			reg = regex_comp(argp[idx].data.str.area, !(argp[idx].type_flags & ARGF_REG_ICASE), 1, &err);
			if (!reg) {
				msg = hlua_pushfstring_safe(L, "error compiling regex '%s' : '%s'",
						            argp[idx].data.str.area, err);
				free(err);
				goto error;
			}
			argp[idx].type = ARGT_REG;
			argp[idx].data.reg = reg;
			break;

		case ARGT_USR:
			if (argp[idx].type != ARGT_STR) {
				msg = "string expected";
				goto error;
			}
			if (p->uri_auth && p->uri_auth->userlist &&
			    strcmp(p->uri_auth->userlist->name, argp[idx].data.str.area) == 0)
				ul = p->uri_auth->userlist;
			else
				ul = auth_find_userlist(argp[idx].data.str.area);

			if (!ul) {
				msg = hlua_pushfstring_safe(L, "unable to find userlist '%s'",
				                            argp[idx].data.str.area);
				goto error;
			}
			argp[idx].type = ARGT_USR;
			argp[idx].data.usr = ul;
			break;

		case ARGT_STR:
			if (!chunk_dup(&tmp, &argp[idx].data.str)) {
				msg = "unable to duplicate string arg";
				goto error;
			}
			argp[idx].data.str = tmp;
			break;

		case ARGT_MAP:
			msg = "type not yet supported";
			goto error;
			break;

		}

		/* Check for type of argument. */
		if ((mask & ARGT_MASK) != argp[idx].type) {
			msg = hlua_pushfstring_safe(L, "'%s' expected, got '%s'",
					            arg_type_names[(mask & ARGT_MASK)],
					            arg_type_names[argp[idx].type & ARGT_MASK]);
			goto error;
		}

		/* Next argument. */
		mask >>= ARGT_BITS;
		idx++;
	}
	return 0;

  error:
	argp[idx].type = ARGT_STOP;
	free_args(argp);
	WILL_LJMP(luaL_argerror(L, first + idx, msg));
	return 0; /* Never reached */
}

/*
 * The following functions are used to make correspondence between the the
 * executed lua pointer and the "struct hlua *" that contain the context.
 *
 *  - hlua_gethlua : return the hlua context associated with an lua_State.
 *  - hlua_sethlua : create the association between hlua context and lua_state.
 */
inline struct hlua *hlua_gethlua(lua_State *L)
{
	struct hlua **hlua = lua_getextraspace(L);
	return *hlua;
}
static inline void hlua_sethlua(struct hlua *hlua)
{
	struct hlua **hlua_store = lua_getextraspace(hlua->T);
	*hlua_store = hlua;
}

/* Will return a non-NULL string indicating the Lua call trace if the caller
 * currently is executing from within a Lua function. One line per entry will
 * be emitted, and each extra line will be prefixed with <pfx>. If a current
 * Lua function is not detected, NULL is returned.
 */
const char *hlua_show_current_location(const char *pfx)
{
	lua_State *L;
	lua_Debug ar;

	/* global or per-thread stack initializing ? */
	if (hlua_state_id != -1 && (L = hlua_states[hlua_state_id]) && lua_getstack(L, 0, &ar))
		return hlua_traceback(L, pfx);

	/* per-thread stack running ? */
	if (hlua_states[tid + 1] && (L = hlua_states[tid + 1]) && lua_getstack(L, 0, &ar))
		return hlua_traceback(L, pfx);

	/* global stack running ? */
	if (hlua_states[0] && (L = hlua_states[0]) && lua_getstack(L, 0, &ar))
		return hlua_traceback(L, pfx);

	return NULL;
}

/* This function is used to send logs. It tries to send them to:
 * - the log target applicable in the current context, OR
 * - stderr when no logger is in use for the current context
 */
static inline void hlua_sendlog(struct proxy *px, int level, const char *msg)
{
	struct tm tm;
	char *p;

	/* Cleanup the log message. */
	p = trash.area;
	for (; *msg != '\0'; msg++, p++) {
		if (p >= trash.area + trash.size - 1) {
			/* Break the message if exceed the buffer size. */
			*(p-4) = ' ';
			*(p-3) = '.';
			*(p-2) = '.';
			*(p-1) = '.';
			break;
		}
		if (isprint((unsigned char)*msg))
			*p = *msg;
		else
			*p = '.';
	}
	*p = '\0';

	if (hlua_log_opts & HLUA_LOG_LOGGERS_ON)
		send_log(px, level, "%s\n", trash.area);

	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		if (!(hlua_log_opts & HLUA_LOG_STDERR_MASK))
			return;

		/* when logging via stderr is set to 'auto', it behaves like 'off' unless one of:
		 * - logging via loggers is disabled
		 * - this is a non-proxy context and there is no global logger configured
		 * - this is a proxy context and the proxy has no logger configured
		 */
		if ((hlua_log_opts & (HLUA_LOG_STDERR_MASK | HLUA_LOG_LOGGERS_ON)) == (HLUA_LOG_STDERR_AUTO | HLUA_LOG_LOGGERS_ON)) {
			/* AUTO=OFF in non-proxy context only if at least one global logger is defined */
			if ((px == NULL) && (!LIST_ISEMPTY(&global.loggers)))
				return;

			/* AUTO=OFF in proxy context only if at least one logger is configured for the proxy */
			if ((px != NULL) && (!LIST_ISEMPTY(&px->loggers)))
				return;
		}

		if (level == LOG_DEBUG && !(global.mode & MODE_DEBUG))
			return;

		get_localtime(date.tv_sec, &tm);
		fprintf(stderr, "[%s] %03d/%02d%02d%02d (%d) : %s\n",
		        log_levels[level], tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec,
		        (int)getpid(), trash.area);
		fflush(stderr);
	}
}

/* This function just ensure that the yield will be always
 * returned with a timeout and permit to set some flags
 * <timeout> is a tick value
 */
__LJMP void hlua_yieldk(lua_State *L, int nresults, lua_KContext ctx,
                        lua_KFunction k, int timeout, unsigned int flags)
{
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		return;
	}

	/* Set the wake timeout. If timeout is required, we set
	 * the expiration time.
	 */
	hlua->wake_time = timeout;

	hlua->flags |= flags;

	/* Process the yield. */
	MAY_LJMP(lua_yieldk(L, nresults, ctx, k));
}

/* This function initialises the Lua environment stored in the stream.
 * It must be called at the start of the stream. This function creates
 * an LUA coroutine. It can not be use to crete the main LUA context.
 *
 * This function is particular. it initialises a new Lua thread. If the
 * initialisation fails (example: out of memory error), the lua function
 * throws an error (longjmp).
 *
 * This function manipulates two Lua stacks: the main and the thread. Only
 * the main stack can fail. The thread is not manipulated. This function
 * MUST NOT manipulate the created thread stack state, because it is not
 * protected against errors thrown by the thread stack.
 */
int hlua_ctx_init(struct hlua *lua, int state_id, struct task *task)
{
	lua->Mref = LUA_REFNIL;
	lua->flags = 0;
	lua->gc_count = 0;
	lua->wake_time = TICK_ETERNITY;
	lua->state_id = state_id;
	hlua_timer_init(&lua->timer, 0); /* default value, no timeout */
	LIST_INIT(&lua->com);
	MT_LIST_INIT(&lua->hc_list);
	if (!SET_SAFE_LJMP_PARENT(lua)) {
		lua->Tref = LUA_REFNIL;
		return 0;
	}
	lua->T = lua_newthread(hlua_states[state_id]);
	if (!lua->T) {
		lua->Tref = LUA_REFNIL;
		RESET_SAFE_LJMP_PARENT(lua);
		return 0;
	}
	hlua_sethlua(lua);
	lua->Tref = luaL_ref(hlua_states[state_id], LUA_REGISTRYINDEX);
	lua->task = task;
	RESET_SAFE_LJMP_PARENT(lua);
	return 1;
}

/* kill all associated httpclient to this hlua task
 * We must take extra precautions as we're manipulating lua-exposed
 * objects without the main lua lock.
 */
static void hlua_httpclient_destroy_all(struct hlua *hlua)
{
	struct hlua_httpclient *hlua_hc;

	/* use thread-safe accessors for hc_list since GC cycle initiated by
	 * another thread sharing the same main lua stack (lua coroutine)
	 * could execute hlua_httpclient_gc() on the hlua->hc_list items
	 * in parallel: Lua GC applies on the main stack, it is not limited to
	 * a single coroutine stack, see Github issue #2037 for reference.
	 * Remember, coroutines created using lua_newthread() are not meant to
	 * be thread safe in Lua. (From lua co-author:
	 * http://lua-users.org/lists/lua-l/2011-07/msg00072.html)
	 *
	 * This security measure is superfluous when 'lua-load-per-thread' is used
	 * since in this case coroutines exclusively run on the same thread
	 * (main stack is not shared between OS threads).
	 */
	while ((hlua_hc = MT_LIST_POP(&hlua->hc_list, typeof(hlua_hc), by_hlua))) {
		httpclient_stop_and_destroy(hlua_hc->hc);
		hlua_hc->hc = NULL;
	}
}


/* Used to destroy the Lua coroutine when the attached stream or task
 * is destroyed. The destroy also the memory context. The struct "lua"
 * will be freed.
 */
void hlua_ctx_destroy(struct hlua *lua)
{
	if (!lua)
		return;

	if (!lua->T)
		goto end;

	/* clean all running httpclient */
	hlua_httpclient_destroy_all(lua);

	/* Purge all the pending signals. */
	notification_purge(&lua->com);

	if (!SET_SAFE_LJMP(lua))
		return;
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	RESET_SAFE_LJMP(lua);

	if (!SET_SAFE_LJMP_PARENT(lua))
		return;
	luaL_unref(hlua_states[lua->state_id], LUA_REGISTRYINDEX, lua->Tref);
	RESET_SAFE_LJMP_PARENT(lua);
	/* Forces a garbage collecting process. If the Lua program is finished
	 * without error, we run the GC on the thread pointer. Its freed all
	 * the unused memory.
	 * If the thread is finnish with an error or is currently yielded,
	 * it seems that the GC applied on the thread doesn't clean anything,
	 * so e run the GC on the main thread.
	 * NOTE: maybe this action locks all the Lua threads untiml the en of
	 * the garbage collection.
	 */
	if (lua->gc_count) {
		if (!SET_SAFE_LJMP_PARENT(lua))
			return;
		lua_gc(hlua_states[lua->state_id], LUA_GCCOLLECT, 0);
		RESET_SAFE_LJMP_PARENT(lua);
	}

	lua->T = NULL;

end:
	pool_free(pool_head_hlua, lua);
}

/* This function is used to restore the Lua context when a coroutine
 * fails. This function copy the common memory between old coroutine
 * and the new coroutine. The old coroutine is destroyed, and its
 * replaced by the new coroutine.
 * If the flag "keep_msg" is set, the last entry of the old is assumed
 * as string error message and it is copied in the new stack.
 */
static int hlua_ctx_renew(struct hlua *lua, int keep_msg)
{
	lua_State *T;
	int new_ref;

	/* New Lua coroutine. */
	T = lua_newthread(hlua_states[lua->state_id]);
	if (!T)
		return 0;

	/* Copy last error message. */
	if (keep_msg)
		lua_xmove(lua->T, T, 1);

	/* Copy data between the coroutines. */
	lua_rawgeti(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	lua_xmove(lua->T, T, 1);
	new_ref = luaL_ref(T, LUA_REGISTRYINDEX); /* Value popped. */

	/* Destroy old data. */
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);

	/* The thread is garbage collected by Lua. */
	luaL_unref(hlua_states[lua->state_id], LUA_REGISTRYINDEX, lua->Tref);

	/* Fill the struct with the new coroutine values. */
	lua->Mref = new_ref;
	lua->T = T;
	lua->Tref = luaL_ref(hlua_states[lua->state_id], LUA_REGISTRYINDEX);

	/* Set context. */
	hlua_sethlua(lua);

	return 1;
}

/* Helper function to get the lua ctx for a given stream and state_id */
static inline struct hlua *hlua_stream_ctx_get(struct stream *s, int state_id)
{
	/* state_id == 0 -> global runtime ctx
	 * state_id != 0 -> per-thread runtime ctx
	 */
	return s->hlua[!!state_id];
}

/* Helper function to prepare the lua ctx for a given stream and state id
 *
 * It uses the global or per-thread ctx depending on the expected
 * <state_id>.
 *
 * Returns hlua ctx on success and NULL on failure
 */
static struct hlua *hlua_stream_ctx_prepare(struct stream *s, int state_id)
{
	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!s->hlua[!!state_id]) {
		struct hlua *hlua;

		hlua = pool_alloc(pool_head_hlua);
		if (!hlua)
			return NULL;
		HLUA_INIT(hlua);
		if (!hlua_ctx_init(hlua, state_id, s->task)) {
			pool_free(pool_head_hlua, hlua);
			return NULL;
		}
		s->hlua[!!state_id] = hlua;
	}
	return s->hlua[!!state_id];
}

void hlua_hook(lua_State *L, lua_Debug *ar)
{
	struct hlua *hlua;
	int timer_check;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return;

	if (hlua->T != L) {
		/* We don't want to enforce a yield on a sub coroutine, since
		 * we have no guarantees that the yield will be handled properly.
		 * Indeed, only the hlua->T coroutine is being handled through
		 * hlua_ctx_resume() function.
		 *
		 * Instead, we simply check for timeouts and wait for the sub
		 * coroutine to finish..
		 */
		goto check_timeout;
	}

	/* Lua cannot yield when its returning from a function,
	 * so, we can fix the interrupt hook to 1 instruction,
	 * expecting that the function is finished.
	 */
	if (lua_gethookmask(L) & LUA_MASKRET) {
		lua_sethook(hlua->T, hlua_hook, LUA_MASKCOUNT, 1);
		return;
	}

	/* If we interrupt the Lua processing in yieldable state, we yield.
	 * If the state is not yieldable, trying yield causes an error.
	 */
	if (lua_isyieldable(L)) {
		/* note: for converters/fetches.. where yielding is not allowed
		 * hlua_ctx_resume() will simply perform a goto resume_execution
		 * instead of rescheduling hlua->task.
		 * also: hlua_ctx_resume() will take care of checking execution
		 * timeout and re-applying the hook as needed.
		 */
		MAY_LJMP(hlua_yieldk(L, 0, 0, NULL, TICK_ETERNITY, HLUA_CTRLYIELD));
		/* lua docs says that the hook should return immediately after lua_yieldk
		 *
		 * From: https://www.lua.org/manual/5.3/manual.html#lua_yieldk
		 *
		 * Moreover, it seems that we don't want to continue after the yield
		 * because the end of the function is about handling unyieldable function,
		 * which is not the case here.
		 *
		 *  ->if we don't return lua_sethook gets incorrectly set with MASKRET later
		 *  in the function.
		 */
		return;
	}

 check_timeout:
	/* If we cannot yield, check the timeout. */
	timer_check = hlua_timer_check(&hlua->timer);
	if (timer_check <= 0) {
		if (!timer_check)
			lua_pushfstring(L, "execution timeout");
		else
			lua_pushfstring(L, "burst timeout");
		WILL_LJMP(lua_error(L));
	}

	/* Try to interrupt the process at the end of the current
	 * unyieldable function.
	 */
	lua_sethook(hlua->T, hlua_hook, LUA_MASKRET|LUA_MASKCOUNT, hlua_get_nb_instruction(hlua));
}

/* This function start or resumes the Lua stack execution. If the flag
 * "yield_allowed" if no set and the  LUA stack execution returns a yield
 * The function return an error.
 *
 * The function can returns 4 values:
 *  - HLUA_E_OK     : The execution is terminated without any errors.
 *  - HLUA_E_AGAIN  : The execution must continue at the next associated
 *                    task wakeup.
 *  - HLUA_E_ERRMSG : An error has occurred, an error message is set in
 *                    the top of the stack.
 *  - HLUA_E_ERR    : An error has occurred without error message.
 *
 * If an error occurred, the stack is renewed and it is ready to run new
 * LUA code.
 */
static enum hlua_exec hlua_ctx_resume(struct hlua *lua, int yield_allowed)
{
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
	int nres;
#endif
	int ret;
	const char *msg;
	const char *trace;

	/* Lock the whole Lua execution. This lock must be before the
	 * label "resume_execution".
	 */
	hlua_lock(lua);

	/* reset the timer as we might be re-entering the function to
	 * resume the coroutine after a successful yield
	 * (cumulative time will be updated)
	 */
	hlua_timer_reset(&lua->timer);

resume_execution:

	/* This hook interrupts the Lua processing each 'hlua_get_nb_instruction()
	 * instructions. it is used for preventing infinite loops.
	 */
	lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, hlua_get_nb_instruction(lua));

	/* Remove all flags except the running flags. */
	HLUA_SET_RUN(lua);
	HLUA_CLR_CTRLYIELD(lua);
	HLUA_CLR_WAKERESWR(lua);
	HLUA_CLR_WAKEREQWR(lua);
	HLUA_CLR_NOYIELD(lua);
	if (!yield_allowed)
		HLUA_SET_NOYIELD(lua);

	/* reset wake_time. */
	lua->wake_time = TICK_ETERNITY;

	/* start the timer as we're about to start lua processing */
	hlua_timer_start(&lua->timer);

	HLUA_SET_BUSY(lua);

	/* Call the function. */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
	ret = lua_resume(lua->T, hlua_states[lua->state_id], lua->nargs, &nres);
#else
	ret = lua_resume(lua->T, hlua_states[lua->state_id], lua->nargs);
#endif

	HLUA_CLR_BUSY(lua);

	/* out of lua processing, stop the timer */
	hlua_timer_stop(&lua->timer);

	/* reset nargs because those possibly passed to the lua_resume() call
	 * were already consumed, and since we may call lua_resume() again
	 * after a successful yield, we don't want to pass stale nargs hint
	 * to the Lua API. As such, nargs should be set explicitly before each
	 * lua_resume() (or hlua_ctx_resume()) invocation if needed.
	 */
	lua->nargs = 0;

	switch (ret) {

	case LUA_OK:
		ret = HLUA_E_OK;
		break;

	case LUA_YIELD:
		/* Check if the execution timeout is expired. If it is the case, we
		 * break the Lua execution.
		 */
		{
			int timer_check;

			timer_check = hlua_timer_check(&lua->timer);
			if (timer_check <= 0) {
				if (!timer_check)
					ret = HLUA_E_ETMOUT;
				else
					ret = HLUA_E_BTMOUT;
				lua_settop(lua->T, 0); /* Empty the stack. */
				break;
			}
		}
		/* Process the forced yield. if the general yield is not allowed or
		 * if no task were associated this the current Lua execution
		 * coroutine, we resume the execution. Else we want to return in the
		 * scheduler and we want to be waked up again, to continue the
		 * current Lua execution. So we schedule our own task.
		 */
		if (HLUA_IS_CTRLYIELDING(lua)) {
			if (!yield_allowed || !lua->task)
				goto resume_execution;
			task_wakeup(lua->task, TASK_WOKEN_MSG);
		}
		if (!yield_allowed) {
			lua_settop(lua->T, 0); /* Empty the stack. */
			ret = HLUA_E_YIELD;
			break;
		}
		ret = HLUA_E_AGAIN;
		break;

	case LUA_ERRRUN:

		/* Special exit case. The traditional exit is returned as an error
		 * because the errors ares the only one mean to return immediately
		 * from and lua execution.
		 */
		if (lua->flags & HLUA_EXIT) {
			ret = HLUA_E_OK;
			hlua_ctx_renew(lua, 1);
			break;
		}

		lua->wake_time = TICK_ETERNITY;
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		msg = hlua_tostring_safe(lua->T, -1);
		trace = hlua_traceback(lua->T, ", ");
		if (msg)
			hlua_pushfstring_safe(lua->T, "[state-id %d] runtime error: %s from %s",
			                      lua->state_id, msg, trace);
		else
			hlua_pushfstring_safe(lua->T, "[state-id %d] unknown runtime error from %s",
			                      lua->state_id, trace);

		/* Move the error msg at the bottom and then empty the stack except last msg */
		lua_insert(lua->T, 1);
		lua_settop(lua->T, 1);
		ret = HLUA_E_ERRMSG;
		break;

	case LUA_ERRMEM:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		ret = HLUA_E_NOMEM;
		break;

	case LUA_ERRERR:
		lua->wake_time = TICK_ETERNITY;
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		msg = hlua_tostring_safe(lua->T, -1);
		if (msg)
			hlua_pushfstring_safe(lua->T, "[state-id %d] message handler error: %s",
			                      lua->state_id, msg);
		else
			hlua_pushfstring_safe(lua->T, "[state-id %d] message handler error",
			                      lua->state_id);

		/* Move the error msg at the bottom and then empty the stack except last msg */
		lua_insert(lua->T, 1);
		lua_settop(lua->T, 1);
		ret = HLUA_E_ERRMSG;
		break;

	default:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		ret = HLUA_E_ERR;
		break;
	}

	switch (ret) {
	case HLUA_E_AGAIN:
		break;

	case HLUA_E_ERRMSG:
		notification_purge(&lua->com);
		hlua_ctx_renew(lua, 1);
		HLUA_CLR_RUN(lua);
		break;

	case HLUA_E_ETMOUT:
	case HLUA_E_BTMOUT:
	case HLUA_E_NOMEM:
	case HLUA_E_YIELD:
	case HLUA_E_ERR:
		HLUA_CLR_RUN(lua);
		notification_purge(&lua->com);
		hlua_ctx_renew(lua, 0);
		break;

	case HLUA_E_OK:
		HLUA_CLR_RUN(lua);
		notification_purge(&lua->com);
		break;
	}

	/* This is the main exit point, remove the Lua lock. */
	hlua_unlock(lua);

	return ret;
}

/* This function exit the current code. */
__LJMP static int hlua_done(lua_State *L)
{
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	hlua->flags |= HLUA_EXIT;
	WILL_LJMP(lua_error(L));

	return 0;
}

/* This function is an LUA binding. It provides a function
 * for deleting ACL from a referenced ACL file.
 */
__LJMP static int hlua_del_acl(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "del_acl"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'del_acl': unknown acl file '%s'", name));

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->lock);
	pat_ref_delete(ref, key);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->lock);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for deleting map entry from a referenced map file.
 */
static int hlua_del_map(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "del_map"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'del_map': unknown acl file '%s'", name));

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->lock);
	pat_ref_delete(ref, key);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->lock);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for adding ACL pattern from a referenced ACL file.
 */
static int hlua_add_acl(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "add_acl"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'add_acl': unknown acl file '%s'", name));

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->lock);
	if (pat_ref_find_elt(ref, key) == NULL)
		pat_ref_add(ref, key, NULL, NULL);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->lock);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for setting map pattern and sample from a referenced map
 * file.
 */
static int hlua_set_map(lua_State *L)
{
	const char *name;
	const char *key;
	const char *value;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 3, "set_map"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));
	value = MAY_LJMP(luaL_checkstring(L, 3));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'set_map': unknown map file '%s'", name));

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->lock);
	if (pat_ref_find_elt(ref, key) != NULL)
		pat_ref_set(ref, key, value, NULL, NULL);
	else
		pat_ref_add(ref, key, value, NULL);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->lock);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for retrieving a var from the proc scope in core.
 */
__LJMP static int hlua_core_get_var(lua_State *L)
{
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 1, "get_var"));

	name = MAY_LJMP(luaL_checklstring(L, 1, &len));

	/* We can only retrieve information from the proc. scope */
	/* FIXME: I didn't want to expose vars_hash_name from vars.c */
	if (len < 5 || strncmp(name, "proc.", 5) != 0)
		WILL_LJMP(luaL_error(L, "'get_var': Only 'proc.' scope allowed to be retrieved in 'core.get_var()'."));

	memset(&smp, 0, sizeof(smp));
	if (!vars_get_by_name(name, len, &smp, NULL)) {
		lua_pushnil(L);
		return 1;
	}

	return MAY_LJMP(hlua_smp2lua(L, &smp));
}

/* This function disables the sending of email through the
 * legacy email sending function which is implemented using
 * checks.
 *
 * It may not be used during runtime.
 */
__LJMP static int hlua_disable_legacy_mailers(lua_State *L)
{
	if (hlua_gethlua(L))
		WILL_LJMP(luaL_error(L, "disable_legacy_mailers: "
		                        "not available outside of init or body context"));
	send_email_disabled = 1;
	return 0;
}

/* A class is a lot of memory that contain data. This data can be a table,
 * an integer or user data. This data is associated with a metatable. This
 * metatable have an original version registered in the global context with
 * the name of the object (_G[<name>] = <metable> ).
 *
 * A metable is a table that modify the standard behavior of a standard
 * access to the associated data. The entries of this new metatable are
 * defined as is:
 *
 * http://lua-users.org/wiki/MetatableEvents
 *
 *    __index
 *
 * we access an absent field in a table, the result is nil. This is
 * true, but it is not the whole truth. Actually, such access triggers
 * the interpreter to look for an __index metamethod: If there is no
 * such method, as usually happens, then the access results in nil;
 * otherwise, the metamethod will provide the result.
 *
 * Control 'prototype' inheritance. When accessing "myTable[key]" and
 * the key does not appear in the table, but the metatable has an __index
 * property:
 *
 * - if the value is a function, the function is called, passing in the
 *   table and the key; the return value of that function is returned as
 *   the result.
 *
 * - if the value is another table, the value of the key in that table is
 *   asked for and returned (and if it doesn't exist in that table, but that
 *   table's metatable has an __index property, then it continues on up)
 *
 * - Use "rawget(myTable,key)" to skip this metamethod.
 *
 * http://www.lua.org/pil/13.4.1.html
 *
 *    __newindex
 *
 * Like __index, but control property assignment.
 *
 *    __mode - Control weak references. A string value with one or both
 *             of the characters 'k' and 'v' which specifies that the the
 *             keys and/or values in the table are weak references.
 *
 *    __call - Treat a table like a function. When a table is followed by
 *             parenthesis such as "myTable( 'foo' )" and the metatable has
 *             a __call key pointing to a function, that function is invoked
 *             (passing any specified arguments) and the return value is
 *             returned.
 *
 *    __metatable - Hide the metatable. When "getmetatable( myTable )" is
 *                  called, if the metatable for myTable has a __metatable
 *                  key, the value of that key is returned instead of the
 *                  actual metatable.
 *
 *    __tostring - Control string representation. When the builtin
 *                 "tostring( myTable )" function is called, if the metatable
 *                 for myTable has a __tostring property set to a function,
 *                 that function is invoked (passing myTable to it) and the
 *                 return value is used as the string representation.
 *
 *    __len - Control table length. When the table length is requested using
 *            the length operator ( '#' ), if the metatable for myTable has
 *            a __len key pointing to a function, that function is invoked
 *            (passing myTable to it) and the return value used as the value
 *            of "#myTable".
 *
 *    __gc - Userdata finalizer code. When userdata is set to be garbage
 *           collected, if the metatable has a __gc field pointing to a
 *           function, that function is first invoked, passing the userdata
 *           to it. The __gc metamethod is not called for tables.
 *           (See http://lua-users.org/lists/lua-l/2006-11/msg00508.html)
 *
 * Special metamethods for redefining standard operators:
 * http://www.lua.org/pil/13.1.html
 *
 *    __add    "+"
 *    __sub    "-"
 *    __mul    "*"
 *    __div    "/"
 *    __unm    "!"
 *    __pow    "^"
 *    __concat ".."
 *
 * Special methods for redefining standard relations
 * http://www.lua.org/pil/13.2.html
 *
 *    __eq "=="
 *    __lt "<"
 *    __le "<="
 */

/*
 *
 *
 * Class Map
 *
 *
 */

/* Returns a struct hlua_map if the stack entry "ud" is
 * a class session, otherwise it throws an error.
 */
__LJMP static struct map_descriptor *hlua_checkmap(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_map_ref));
}

/* This function is the map constructor. It don't need
 * the class Map object. It creates and return a new Map
 * object. It must be called only during "body" or "init"
 * context because it process some filesystem accesses.
 */
__LJMP static int hlua_map_new(struct lua_State *L)
{
	const char *fn;
	int match = PAT_MATCH_STR;
	struct sample_conv conv;
	const char *file = "";
	int line = 0;
	lua_Debug ar;
	char *err = NULL;
	struct arg args[2];

	if (lua_gettop(L) < 1 || lua_gettop(L) > 2)
		WILL_LJMP(luaL_error(L, "'new' needs at least 1 argument."));

	fn = MAY_LJMP(luaL_checkstring(L, 1));

	if (lua_gettop(L) >= 2) {
		match = MAY_LJMP(luaL_checkinteger(L, 2));
		if (match < 0 || match >= PAT_MATCH_NUM)
			WILL_LJMP(luaL_error(L, "'new' needs a valid match method."));
	}

	/* Get Lua filename and line number. */
	if (lua_getstack(L, 1, &ar)) {  /* check function at level */
		lua_getinfo(L, "Sl", &ar);  /* get info about it */
		if (ar.currentline > 0) {  /* is there info? */
			file = ar.short_src;
			line = ar.currentline;
		}
	}

	/* fill fake sample_conv struct. */
	conv.kw = ""; /* unused. */
	conv.process = NULL; /* unused. */
	conv.arg_mask = 0; /* unused. */
	conv.val_args = NULL; /* unused. */
	conv.out_type = SMP_T_STR;
	conv.private = (void *)(long)match;
	switch (match) {
	case PAT_MATCH_STR: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_BEG: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_SUB: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_DIR: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_DOM: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_END: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_REG: conv.in_type = SMP_T_STR;  break;
	case PAT_MATCH_INT: conv.in_type = SMP_T_SINT; break;
	case PAT_MATCH_IP:  conv.in_type = SMP_T_ADDR; break;
	default:
		WILL_LJMP(luaL_error(L, "'new' doesn't support this match mode."));
	}

	/* fill fake args. */
	args[0].type = ARGT_STR;
	args[0].data.str.area = strdup(fn);
	args[0].data.str.data = strlen(fn);
	args[0].data.str.size = args[0].data.str.data+1;
	args[1].type = ARGT_STOP;

	/* load the map. */
	if (!sample_load_map(args, &conv, file, line, &err)) {
		/* error case: we can't use luaL_error because we must
		 * free the err variable.
		 */
		hlua_pusherror(L, "'new': %s.", err);
		free(err);
		chunk_destroy(&args[0].data.str);
		WILL_LJMP(lua_error(L));
	}

	/* create the lua object. */
	lua_newtable(L);
	lua_pushlightuserdata(L, args[0].data.map);
	lua_rawseti(L, -2, 0);

	/* Pop a class Map metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_map_ref);
	lua_setmetatable(L, -2);


	return 1;
}

__LJMP static inline int _hlua_map_lookup(struct lua_State *L, int str)
{
	struct map_descriptor *desc;
	struct pattern *pat;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "lookup"));
	desc = MAY_LJMP(hlua_checkmap(L, 1));
	if (desc->pat.expect_type == SMP_T_SINT) {
		smp.data.type = SMP_T_SINT;
		smp.data.u.sint = MAY_LJMP(luaL_checkinteger(L, 2));
	}
	else {
		smp.data.type = SMP_T_STR;
		smp.flags = SMP_F_CONST;
		smp.data.u.str.area = (char *)MAY_LJMP(luaL_checklstring(L, 2, (size_t *)&smp.data.u.str.data));
		smp.data.u.str.size = smp.data.u.str.data + 1;
	}

	pat = pattern_exec_match(&desc->pat, &smp, 1);
	if (!pat || !pat->data) {
		if (str)
			lua_pushstring(L, "");
		else
			lua_pushnil(L);
		return 1;
	}

	/* The Lua pattern must return a string, so we can't check the returned type */
	lua_pushlstring(L, pat->data->u.str.area, pat->data->u.str.data);
	return 1;
}

__LJMP static int hlua_map_lookup(struct lua_State *L)
{
	return _hlua_map_lookup(L, 0);
}

__LJMP static int hlua_map_slookup(struct lua_State *L)
{
	return _hlua_map_lookup(L, 1);
}

/*
 *
 *
 * Class Socket
 *
 *
 */

__LJMP static struct hlua_socket *hlua_checksocket(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_socket_ref));
}

/* This function is the handler called for each I/O on the established
 * connection. It is used for notify space available to send or data
 * received.
 */
static void hlua_socket_handler(struct appctx *appctx)
{
	struct hlua_csk_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR)))) {
		co_skip(sc_oc(sc), co_data(sc_oc(sc)));
		notification_wake(&ctx->wake_on_read);
		notification_wake(&ctx->wake_on_write);
		return;
	}

	if (ctx->die) {
		se_fl_set(appctx->sedesc, SE_FL_EOI|SE_FL_EOS);
		notification_wake(&ctx->wake_on_read);
		notification_wake(&ctx->wake_on_write);
		return;
	}

	/* If we can't write, wakeup the pending write signals. */
	if (channel_output_closed(sc_ic(sc)))
		notification_wake(&ctx->wake_on_write);

	/* If we can't read, wakeup the pending read signals. */
	if (channel_input_closed(sc_oc(sc)))
		notification_wake(&ctx->wake_on_read);

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (sc_opposite(sc)->state < SC_ST_EST) {
		applet_need_more_data(appctx);
		se_need_remote_conn(appctx->sedesc);
		applet_have_more_data(appctx);
		return;
	}

	/* This function is called after the connect. */
	ctx->connected = 1;

	/* Wake the tasks which wants to write if the buffer have available space. */
	if (channel_may_recv(sc_ic(sc)))
		notification_wake(&ctx->wake_on_write);

	/* Wake the tasks which wants to read if the buffer contains data. */
	if (co_data(sc_oc(sc))) {
		notification_wake(&ctx->wake_on_read);
		applet_wont_consume(appctx);
	}

	/* If write notifications are registered, we considers we want
	 * to write, so we clear the blocking flag.
	 */
	if (notification_registered(&ctx->wake_on_write))
		applet_have_more_data(appctx);
}

static int hlua_socket_init(struct appctx *appctx)
{
	struct hlua_csk_ctx *csk_ctx = appctx->svcctx;
	struct stream *s;

	if (appctx_finalize_startup(appctx, socket_proxy, &BUF_NULL) == -1)
		goto error;

	s = appctx_strm(appctx);

	/* Configure "right" stream connector. This stconn is used to connect
	 * and retrieve data from the server. The connection is initialized
	 * with the "struct server".
	 */
	sc_set_state(s->scb, SC_ST_ASS);

	/* Force destination server. */
	s->flags |= SF_DIRECT | SF_ASSIGNED | SF_BE_ASSIGNED;
	s->target = &csk_ctx->srv->obj_type;

	if (csk_ctx->timeout) {
		s->sess->fe->timeout.connect = csk_ctx->timeout;
		s->scf->ioto = csk_ctx->timeout;
		s->scb->ioto = csk_ctx->timeout;
	}

	return 0;

  error:
	return -1;
}

/* This function is called when the "struct stream" is destroyed.
 * Remove the link from the object to this stream.
 * Wake all the pending signals.
 */
static void hlua_socket_release(struct appctx *appctx)
{
	struct hlua_csk_ctx *ctx = appctx->svcctx;
	struct xref *peer;

	/* Remove my link in the original objects. */
	peer = xref_get_peer_and_lock(&ctx->xref);
	if (peer)
		xref_disconnect(&ctx->xref, peer);

	/* Wake all the task waiting for me. */
	notification_wake(&ctx->wake_on_read);
	notification_wake(&ctx->wake_on_write);
}

/* If the garbage collectio of the object is launch, nobody
 * uses this object. If the stream does not exists, just quit.
 * Send the shutdown signal to the stream. In some cases,
 * pending signal can rest in the read and write lists. destroy
 * it.
 */
__LJMP static int hlua_socket_gc(lua_State *L)
{
	struct hlua_socket *socket;
	struct hlua_csk_ctx *ctx;
	struct xref *peer;

	MAY_LJMP(check_args(L, 1, "__gc"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer)
		return 0;

	ctx = container_of(peer, struct hlua_csk_ctx, xref);

	/* Remove all reference between the Lua stack and the coroutine stream. */
	xref_disconnect(&socket->xref, peer);

	if (se_fl_test(ctx->appctx->sedesc, SE_FL_ORPHAN)) {
		/* The applet was never initialized, just release it */
		appctx_free(ctx->appctx);
	}
	else {
		/* Otherwise, notify it that is must die and wake it up */
		ctx->die = 1;
		appctx_wakeup(ctx->appctx);
	}

	return 0;
}

/* The close function send shutdown signal and break the
 * links between the stream and the object.
 */
__LJMP static int hlua_socket_close_helper(lua_State *L)
{
	struct hlua_socket *socket;
	struct hlua_csk_ctx *ctx;
	struct xref *peer;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer)
		return 0;

	hlua->gc_count--;
	ctx = container_of(peer, struct hlua_csk_ctx, xref);

	/* Set the flag which destroy the session. */
	ctx->die = 1;
	appctx_wakeup(ctx->appctx);

	/* Remove all reference between the Lua stack and the coroutine stream. */
	xref_disconnect(&socket->xref, peer);
	return 0;
}

/* The close function calls close_helper.
 */
__LJMP static int hlua_socket_close(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "close"));
	return hlua_socket_close_helper(L);
}

/* This Lua function assumes that the stack contain three parameters.
 *  1 - USERDATA containing a struct socket
 *  2 - INTEGER with values of the macro defined below
 *      If the integer is -1, we must read at most one line.
 *      If the integer is -2, we ust read all the data until the
 *      end of the stream.
 *      If the integer is positive value, we must read a number of
 *      bytes corresponding to this value.
 */
#define HLSR_READ_LINE (-1)
#define HLSR_READ_ALL (-2)
__LJMP static int hlua_socket_receive_yield(struct lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_socket *socket = MAY_LJMP(hlua_checksocket(L, 1));
	int wanted = lua_tointeger(L, 2);
	struct hlua *hlua;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	size_t len;
	int nblk;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;
	int skip_at_end = 0;
	struct channel *oc;
	struct stream *s;
	struct xref *peer;
	int missing_bytes;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'receive' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer)
		goto no_peer;

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	if (!csk_ctx->connected)
		goto connection_closed;

	appctx = csk_ctx->appctx;
	s = appctx_strm(appctx);

	oc = &s->res;
	if (wanted == HLSR_READ_LINE) {
		/* Read line. */
		nblk = co_getline_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data available. */
			goto connection_empty;

		/* remove final \r\n. */
		if (nblk == 1) {
			if (blk1[len1-1] == '\n') {
				len1--;
				skip_at_end++;
				if (blk1[len1-1] == '\r') {
					len1--;
					skip_at_end++;
				}
			}
		}
		else {
			if (blk2[len2-1] == '\n') {
				len2--;
				skip_at_end++;
				if (blk2[len2-1] == '\r') {
					len2--;
					skip_at_end++;
				}
			}
		}
	}

	else if (wanted == HLSR_READ_ALL) {
		/* Read all the available data. */
		nblk = co_getblk_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data available. */
			goto connection_empty;
	}

	else {
		/* Read a block of data. */
		nblk = co_getblk_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data available. */
			goto connection_empty;

		missing_bytes = wanted - socket->b.n;
		if (len1 > missing_bytes) {
			nblk = 1;
			len1 = missing_bytes;
		} if (nblk == 2 && len1 + len2 > missing_bytes)
			len2 = missing_bytes - len1;
	}

	len = len1;

	luaL_addlstring(&socket->b, blk1, len1);
	if (nblk == 2) {
		len += len2;
		luaL_addlstring(&socket->b, blk2, len2);
	}

	/* Consume data. */
	co_skip(oc, len + skip_at_end);

	/* Don't wait anything. */
	applet_will_consume(appctx);
	appctx_wakeup(appctx);

	/* If the pattern reclaim to read all the data
	 * in the connection, got out.
	 */
	if (wanted == HLSR_READ_ALL)
		goto connection_empty;
	else if (wanted >= 0 && socket->b.n < wanted)
		goto connection_empty;

	/* Return result. */
	luaL_pushresult(&socket->b);
	xref_unlock(&socket->xref, peer);
	return 1;

connection_closed:

	xref_unlock(&socket->xref, peer);

no_peer:

	/* If the buffer containds data. */
	if (socket->b.n > 0) {
		luaL_pushresult(&socket->b);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, "connection closed.");
	return 2;

connection_empty:

	if (!notification_new(&hlua->com, &csk_ctx->wake_on_read, hlua->task)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "out of memory"));
	}
	xref_unlock(&socket->xref, peer);
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_receive_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This Lua function gets two parameters. The first one can be string
 * or a number. If the string is "*l", the user requires one line. If
 * the string is "*a", the user requires all the contents of the stream.
 * If the value is a number, the user require a number of bytes equal
 * to the value. The default value is "*l" (a line).
 *
 * This parameter with a variable type is converted in integer. This
 * integer takes this values:
 *  -1 : read a line
 *  -2 : read all the stream
 *  >0 : amount of bytes.
 *
 * The second parameter is optional. It contains a string that must be
 * concatenated with the read data.
 */
__LJMP static int hlua_socket_receive(struct lua_State *L)
{
	int wanted = HLSR_READ_LINE;
	const char *pattern;
	int lastarg, type;
	char *error;
	size_t len;
	struct hlua_socket *socket;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "The 'receive' function requires between 1 and 3 arguments."));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for pattern. */
	if (lua_gettop(L) >= 2) {
		type = lua_type(L, 2);
		if (type == LUA_TSTRING) {
			pattern = lua_tostring(L, 2);
			if (strcmp(pattern, "*a") == 0)
				wanted = HLSR_READ_ALL;
			else if (strcmp(pattern, "*l") == 0)
				wanted = HLSR_READ_LINE;
			else {
				wanted = strtoll(pattern, &error, 10);
				if (*error != '\0')
					WILL_LJMP(luaL_error(L, "Unsupported pattern."));
			}
		}
		else if (type == LUA_TNUMBER) {
			wanted = lua_tointeger(L, 2);
			if (wanted < 0)
				WILL_LJMP(luaL_error(L, "Unsupported size."));
		}
	}

	/* Set pattern. */
	lua_pushinteger(L, wanted);

	/* Check if we would replace the top by itself. */
	if (lua_gettop(L) != 2)
		lua_replace(L, 2);

	/* Save index of the top of the stack because since buffers are used, it
	 * may change
	 */
	lastarg = lua_gettop(L);

	/* init buffer, and fill it with prefix. */
	luaL_buffinit(L, &socket->b);

	/* Check prefix. */
	if (lastarg >= 3) {
		if (lua_type(L, 3) != LUA_TSTRING)
			WILL_LJMP(luaL_error(L, "Expect a 'string' for the prefix"));
		pattern = lua_tolstring(L, 3, &len);
		luaL_addlstring(&socket->b, pattern, len);
	}

	return __LJMP(hlua_socket_receive_yield(L, 0, 0));
}

/* Write the Lua input string in the output buffer.
 * This function returns a yield if no space is available.
 */
static int hlua_socket_write_yield(struct lua_State *L,int status, lua_KContext ctx)
{
	struct hlua_socket *socket;
	struct hlua *hlua;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	size_t buf_len;
	const char *buf;
	int len;
	int send_len;
	int sent;
	struct xref *peer;
	struct stream *s;
	struct stconn *sc;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'write' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* Get object */
	socket = MAY_LJMP(hlua_checksocket(L, 1));
	buf = MAY_LJMP(luaL_checklstring(L, 2, &buf_len));
	sent = MAY_LJMP(luaL_checkinteger(L, 3));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushinteger(L, -1);
		return 1;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	if (!csk_ctx->connected) {
		xref_unlock(&socket->xref, peer);
		lua_pushinteger(L, -1);
		return 1;
	}

	appctx = csk_ctx->appctx;
	sc = appctx_sc(appctx);
	s = __sc_strm(sc);

	/* Check for connection close. */
	if (channel_output_closed(&s->req)) {
		xref_unlock(&socket->xref, peer);
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Update the input buffer data. */
	buf += sent;
	send_len = buf_len - sent;

	/* All the data are sent. */
	if (sent >= buf_len) {
		xref_unlock(&socket->xref, peer);
		return 1; /* Implicitly return the length sent. */
	}

	/* Check if the buffer is available because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (s->req.buf.size == 0) {
		if (!sc_alloc_ibuf(sc, &appctx->buffer_wait))
			goto hlua_socket_write_yield_return;
	}

	/* Check for available space. */
	len = b_room(&s->req.buf);
	if (len <= 0) {
		goto hlua_socket_write_yield_return;
	}

	/* send data */
	if (len < send_len)
		send_len = len;
	len = ci_putblk(&s->req, buf, send_len);

	/* "Not enough space" (-1), "Buffer too little to contain
	 * the data" (-2) are not expected because the available length
	 * is tested.
	 * Other unknown error are also not expected.
	 */
	if (len <= 0) {
		if (len == -1)
			s->req.flags |= CF_WAKE_WRITE;

		MAY_LJMP(hlua_socket_close_helper(L));
		lua_pop(L, 1);
		lua_pushinteger(L, -1);
		xref_unlock(&socket->xref, peer);
		return 1;
	}

	/* update buffers. */
	appctx_wakeup(appctx);

	/* Update length sent. */
	lua_pop(L, 1);
	lua_pushinteger(L, sent + len);

	/* All the data buffer is sent ? */
	if (sent + len >= buf_len) {
		xref_unlock(&socket->xref, peer);
		return 1;
	}

hlua_socket_write_yield_return:
	if (!notification_new(&hlua->com, &csk_ctx->wake_on_write, hlua->task)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "out of memory"));
	}
	xref_unlock(&socket->xref, peer);
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_write_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function initiate the send of data. It just check the input
 * parameters and push an integer in the Lua stack that contain the
 * amount of data written to the buffer. This is used by the function
 * "hlua_socket_write_yield" that can yield.
 *
 * The Lua function gets between 3 and 4 parameters. The first one is
 * the associated object. The second is a string buffer. The third is
 * a facultative integer that represents where is the buffer position
 * of the start of the data that can send. The first byte is the
 * position "1". The default value is "1". The fourth argument is a
 * facultative integer that represents where is the buffer position
 * of the end of the data that can send. The default is the last byte.
 */
static int hlua_socket_send(struct lua_State *L)
{
	int i;
	int j;
	const char *buf;
	size_t buf_len;

	/* Check number of arguments. */
	if (lua_gettop(L) < 2 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'send' needs between 2 and 4 arguments"));

	/* Get the string. */
	buf = MAY_LJMP(luaL_checklstring(L, 2, &buf_len));

	/* Get and check j. */
	if (lua_gettop(L) == 4) {
		j = MAY_LJMP(luaL_checkinteger(L, 4));
		if (j < 0)
			j = buf_len + j + 1;
		if (j > buf_len)
			j = buf_len + 1;
		lua_pop(L, 1);
	}
	else
		j = buf_len;

	/* Get and check i. */
	if (lua_gettop(L) == 3) {
		i = MAY_LJMP(luaL_checkinteger(L, 3));
		if (i < 0)
			i = buf_len + i + 1;
		if (i > buf_len)
			i = buf_len + 1;
		lua_pop(L, 1);
	} else
		i = 1;

	/* Check bth i and j. */
	if (i > j) {
		lua_pushinteger(L, 0);
		return 1;
	}
	if (i == 0 && j == 0) {
		lua_pushinteger(L, 0);
		return 1;
	}
	if (i == 0)
		i = 1;
	if (j == 0)
		j = 1;

	/* Pop the string. */
	lua_pop(L, 1);

	/* Update the buffer length. */
	buf += i - 1;
	buf_len = j - i + 1;
	lua_pushlstring(L, buf, buf_len);

	/* This unsigned is used to remember the amount of sent data. */
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_socket_write_yield(L, 0, 0));
}

#define SOCKET_INFO_MAX_LEN sizeof("[0000:0000:0000:0000:0000:0000:0000:0000]:12345")
__LJMP static inline int hlua_socket_info(struct lua_State *L, const struct sockaddr_storage *addr)
{
	static char buffer[SOCKET_INFO_MAX_LEN];
	int ret;
	int len;
	char *p;

	ret = addr_to_str(addr, buffer+1, SOCKET_INFO_MAX_LEN-1);
	if (ret <= 0) {
		lua_pushnil(L);
		return 1;
	}

	if (ret == AF_UNIX) {
		lua_pushstring(L, buffer+1);
		return 1;
	}
	else if (ret == AF_INET6) {
		buffer[0] = '[';
		len = strlen(buffer);
		buffer[len] = ']';
		len++;
		buffer[len] = ':';
		len++;
		p = buffer;
	}
	else if (ret == AF_INET) {
		p = buffer + 1;
		len = strlen(p);
		p[len] = ':';
		len++;
	}
	else {
		lua_pushnil(L);
		return 1;
	}

	if (port_to_str(addr, p + len, SOCKET_INFO_MAX_LEN-1 - len) <= 0) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, p);
	return 1;
}

/* Returns information about the peer of the connection. */
__LJMP static int hlua_socket_getpeername(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct xref *peer;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	struct stconn *sc;
	const struct sockaddr_storage *dst;
	int ret;

	MAY_LJMP(check_args(L, 1, "getpeername"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		return 1;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	if (!csk_ctx->connected) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		return 1;
	}

	appctx = csk_ctx->appctx;
	sc = appctx_sc(appctx);
	dst = sc_dst(sc_opposite(sc));
	if (!dst) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		return 1;
	}

	ret = MAY_LJMP(hlua_socket_info(L, dst));
	xref_unlock(&socket->xref, peer);
	return ret;
}

/* Returns information about my connection side. */
static int hlua_socket_getsockname(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct connection *conn;
	struct appctx *appctx;
	struct xref *peer;
	struct hlua_csk_ctx *csk_ctx;
	struct stream *s;
	int ret;

	MAY_LJMP(check_args(L, 1, "getsockname"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		return 1;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	if (!csk_ctx->connected) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		return 1;
	}

	appctx = csk_ctx->appctx;
	s = appctx_strm(appctx);

	conn = sc_conn(s->scb);
	if (!conn || !conn_get_src(conn)) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		return 1;
	}

	ret = hlua_socket_info(L, conn->src);
	xref_unlock(&socket->xref, peer);
	return ret;
}

/* This struct define the applet. */
static struct applet update_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<LUA_TCP>",
	.fct = hlua_socket_handler,
	.init = hlua_socket_init,
	.release = hlua_socket_release,
};

__LJMP static int hlua_socket_connect_yield(struct lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_socket *socket = MAY_LJMP(hlua_checksocket(L, 1));
	struct hlua *hlua;
	struct xref *peer;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	struct stream *s;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		lua_pushstring(L, "Can't connect");
		return 2;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	appctx = csk_ctx->appctx;
	s = appctx_strm(appctx);

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));
	}

	/* Check for connection close. */
	if (!hlua || channel_output_closed(&s->req)) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		lua_pushstring(L, "Can't connect");
		return 2;
	}

	appctx = __sc_appctx(s->scf);

	/* Check for connection established. */
	if (csk_ctx->connected) {
		xref_unlock(&socket->xref, peer);
		lua_pushinteger(L, 1);
		return 1;
	}

	if (!notification_new(&hlua->com, &csk_ctx->wake_on_write, hlua->task)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "out of memory error"));
	}
	xref_unlock(&socket->xref, peer);
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function fail or initite the connection. */
__LJMP static int hlua_socket_connect(struct lua_State *L)
{
	struct hlua_socket *socket;
	int port = -1;
	const char *ip;
	struct hlua *hlua;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	int low, high;
	struct sockaddr_storage *addr;
	struct xref *peer;
	struct stconn *sc;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	if (lua_gettop(L) < 2)
		WILL_LJMP(luaL_error(L, "connect: need at least 2 arguments"));

	/* Get args. */
	socket  = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	ip      = MAY_LJMP(luaL_checkstring(L, 2));
	if (lua_gettop(L) >= 3) {
		luaL_Buffer b;
		port = MAY_LJMP(luaL_checkinteger(L, 3));

		/* Force the ip to end with a colon, to support IPv6 addresses
		 * that are not enclosed within square brackets.
		 */
		if (port > 0) {
			luaL_buffinit(L, &b);
			luaL_addstring(&b, ip);
			luaL_addchar(&b, ':');
			luaL_pushresult(&b);
			ip = lua_tolstring(L, lua_gettop(L), NULL);
		}
	}

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		return 1;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	if (!csk_ctx->srv)
		csk_ctx->srv = socket_tcp;

	/* Parse ip address. */
	addr = str2sa_range(ip, NULL, &low, &high, NULL, NULL, NULL, NULL,
	                    NULL, NULL, NULL, PA_O_PORT_OK | PA_O_STREAM);
	if (!addr) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: cannot parse destination address '%s'", ip));
	}

	/* Set port. */
	if (low == 0) {
		if (addr->ss_family == AF_INET) {
			if (port == -1) {
				xref_unlock(&socket->xref, peer);
				WILL_LJMP(luaL_error(L, "connect: port missing"));
			}
			((struct sockaddr_in *)addr)->sin_port = htons(port);
		} else if (addr->ss_family == AF_INET6) {
			if (port == -1) {
				xref_unlock(&socket->xref, peer);
				WILL_LJMP(luaL_error(L, "connect: port missing"));
			}
			((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		}
	}

	appctx = csk_ctx->appctx;
	if (appctx_sc(appctx)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: connect already performed\n"));
	}

	if (appctx_init(appctx) == -1) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: fail to init applet."));
	}

	sc = appctx_sc(appctx);

	if (!sockaddr_alloc(&sc_opposite(sc)->dst, addr, sizeof(*addr))) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: internal error"));
	}

	/* inform the stream that we want to be notified whenever the
	 * connection completes.
	 */
	applet_need_more_data(appctx);
	applet_have_more_data(appctx);
	appctx_wakeup(appctx);

	if (!notification_new(&hlua->com, &csk_ctx->wake_on_write, hlua->task)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "out of memory"));
	}
	xref_unlock(&socket->xref, peer);

	/* Return yield waiting for connection. */
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));

	return 0;
}

#ifdef USE_OPENSSL
__LJMP static int hlua_socket_connect_ssl(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct xref *peer;

	MAY_LJMP(check_args(L, 3, "connect_ssl"));
	socket  = MAY_LJMP(hlua_checksocket(L, 1));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		return 1;
	}

	container_of(peer, struct hlua_csk_ctx, xref)->srv = socket_ssl;

	xref_unlock(&socket->xref, peer);
	return MAY_LJMP(hlua_socket_connect(L));
}
#endif

__LJMP static int hlua_socket_setoption(struct lua_State *L)
{
	return 0;
}

__LJMP static int hlua_socket_settimeout(struct lua_State *L)
{
	struct hlua_socket *socket;
	int tmout;
	double dtmout;
	struct xref *peer;
	struct hlua_csk_ctx *csk_ctx;
	struct appctx *appctx;
	struct stream *s;

	MAY_LJMP(check_args(L, 2, "settimeout"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* convert the timeout to millis */
	dtmout = MAY_LJMP(luaL_checknumber(L, 2)) * 1000;

	/* Check for negative values */
	if (dtmout < 0)
		WILL_LJMP(luaL_error(L, "settimeout: cannot set negatives values"));

	if (dtmout > INT_MAX) /* overflow check */
		WILL_LJMP(luaL_error(L, "settimeout: cannot set values larger than %d ms", INT_MAX));

	tmout = MS_TO_TICKS((int)dtmout);
	if (tmout == 0)
		tmout++; /* very small timeouts are adjusted to a minimum of 1ms */

	/* Check if we run on the same thread than the xreator thread.
	 * We cannot access to the socket if the thread is different.
	 */
	if (socket->tid != tid)
		WILL_LJMP(luaL_error(L, "connect: cannot use socket on other thread"));

	/* check for connection break. If some data were read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		hlua_pusherror(L, "socket: not yet initialised, you can't set timeouts.");
		WILL_LJMP(lua_error(L));
		return 0;
	}

	csk_ctx = container_of(peer, struct hlua_csk_ctx, xref);
	csk_ctx->timeout = tmout;

	appctx = csk_ctx->appctx;
	if (!appctx_sc(appctx))
		goto end;

	s = appctx_strm(csk_ctx->appctx);

	s->sess->fe->timeout.connect = tmout;
	s->scf->ioto = tmout;
	s->scb->ioto = tmout;

	s->task->expire = (tick_is_expired(s->task->expire, now_ms) ? 0 : s->task->expire);
	s->task->expire = tick_first(s->task->expire, tick_add_ifset(now_ms, tmout));
	task_queue(s->task);

  end:
	xref_unlock(&socket->xref, peer);
	lua_pushinteger(L, 1);
	return 1;
}

__LJMP static int hlua_socket_new(lua_State *L)
{
	struct hlua_socket *socket;
	struct hlua_csk_ctx *ctx;
	struct appctx *appctx;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	/* Check stack size. */
	if (!lua_checkstack(L, 3)) {
		hlua_pusherror(L, "socket: full stack");
		goto out_fail_conf;
	}

	/* Create the object: obj[0] = userdata. */
	lua_newtable(L);
	socket = MAY_LJMP(lua_newuserdata(L, sizeof(*socket)));
	lua_rawseti(L, -2, 0);
	memset(socket, 0, sizeof(*socket));
	socket->tid = tid;

	/* Check if the various memory pools are initialized. */
	if (!pool_head_stream || !pool_head_buffer) {
		hlua_pusherror(L, "socket: uninitialized pools.");
		goto out_fail_conf;
	}

	/* Pop a class stream metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_socket_ref);
	lua_setmetatable(L, -2);

	/* Create the applet context */
	appctx = appctx_new_here(&update_applet, NULL);
	if (!appctx) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_conf;
	}
	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	ctx->connected = 0;
	ctx->die = 0;
	ctx->srv = NULL;
	ctx->timeout = 0;
	ctx->appctx = appctx;
	LIST_INIT(&ctx->wake_on_write);
	LIST_INIT(&ctx->wake_on_read);

	hlua->gc_count++;

	/* Initialise cross reference between stream and Lua socket object. */
	xref_create(&socket->xref, &ctx->xref);
	return 1;

 out_fail_conf:
	WILL_LJMP(lua_error(L));
	return 0;
}

/*
 *
 *
 * Class Channel
 *
 *
 */

/* Returns the struct hlua_channel join to the class channel in the
 * stack entry "ud" or throws an argument error.
 */
__LJMP static struct channel *hlua_checkchannel(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_channel_ref));
}

/* Pushes the channel onto the top of the stack. If the stask does not have a
 * free slots, the function fails and returns 0;
 */
__LJMP static int hlua_channel_new(lua_State *L, struct channel *channel)
{
	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	lua_newtable(L);
	lua_pushlightuserdata(L, channel);
	lua_rawseti(L, -2, 0);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_channel_ref);
	lua_setmetatable(L, -2);
	return 1;
}

/* Helper function returning a filter attached to a channel at the position <ud>
 * in the stack, filling the current offset and length of the filter. If no
 * filter is attached, NULL is returned and <offset> and <len> are not
 * initialized.
 */
static struct filter *hlua_channel_filter(lua_State *L, int ud, struct channel *chn, size_t *offset, size_t *len)
{
	struct filter *filter = NULL;

	if (lua_getfield(L, ud, "__filter") == LUA_TLIGHTUSERDATA) {
		struct hlua_flt_ctx *flt_ctx;

		filter  = lua_touserdata (L, -1);
		flt_ctx = filter->ctx;
		if (hlua_filter_from_payload(filter)) {
			*offset  = flt_ctx->cur_off[CHN_IDX(chn)];
			*len     = flt_ctx->cur_len[CHN_IDX(chn)];
		}
	}

	lua_pop(L, 1);
	return filter;
}

/* Copies <len> bytes of data present in the channel's buffer, starting at the
* offset <offset>, and put it in a LUA string variable. It is the caller
* responsibility to ensure <len> and <offset> are valid. It always return the
* length of the built string. <len> may be 0, in this case, an empty string is
* created and 0 is returned.
*/
static inline int _hlua_channel_dup(struct channel *chn, lua_State *L, size_t offset, size_t len)
{
	size_t block1, block2;
	luaL_Buffer b;

	block1 = len;
	if (block1 > b_contig_data(&chn->buf, b_peek_ofs(&chn->buf, offset)))
		block1 = b_contig_data(&chn->buf, b_peek_ofs(&chn->buf, offset));
	block2 = len - block1;

	luaL_buffinit(L, &b);
	luaL_addlstring(&b, b_peek(&chn->buf, offset), block1);
	if (block2)
		luaL_addlstring(&b, b_orig(&chn->buf), block2);
	luaL_pushresult(&b);
	return len;
}

/* Inserts the string <str> to the channel's buffer at the offset <offset>. This
 * function returns -1 if data cannot be copied. Otherwise, it returns the
 * number of bytes copied.
 */
static int _hlua_channel_insert(struct channel *chn, lua_State *L, struct ist str, size_t offset)
{
	int ret = 0;

	/* Nothing to do, just return */
	if (unlikely(istlen(str) == 0))
		goto end;

	if (istlen(str) > c_room(chn)) {
		ret = -1;
		goto end;
	}
	ret = b_insert_blk(&chn->buf, offset, istptr(str), istlen(str));

  end:
	return ret;
}

/* Removes <len> bytes of data at the absolute position <offset>.
 */
static void _hlua_channel_delete(struct channel *chn, size_t offset, size_t len)
{
	size_t end = offset + len;

	if (b_peek(&chn->buf, end) != b_tail(&chn->buf))
		b_move(&chn->buf, b_peek_ofs(&chn->buf, end),
		       b_data(&chn->buf) - end, -len);
	b_sub(&chn->buf, len);
}

/* Copies input data in the channel's buffer. It is possible to set a specific
 * offset (0 by default) and a length (all remaining input data starting for the
 * offset by default). If there is not enough input data and more data can be
 * received, this function yields.
 *
 * From an action, All input data are considered. For a filter, the offset and
 * the length of input data to consider are retrieved from the filter context.
 */
__LJMP static int hlua_channel_get_data_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	struct filter *filter;
	size_t input, output;
	int offset, len;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	output = co_data(chn);
	input = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 1) {
		offset = MAY_LJMP(luaL_checkinteger(L, 2));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}
	len = output + input - offset;
	if (lua_gettop(L) == 3) {
		len = MAY_LJMP(luaL_checkinteger(L, 3));
		if (!len)
			goto dup;
		if (len == -1)
			len = global.tune.bufsize;
		if (len < 0) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	/* Wait for more data if possible if no length was specified and there
	 * is no data or not enough data was received.
	 */
	if (!len || offset + len > output + input) {
		if (!HLUA_CANT_YIELD(hlua_gethlua(L)) && !channel_input_closed(chn) && channel_may_recv(chn)) {
			/* Yield waiting for more data, as requested */
			MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_get_data_yield, TICK_ETERNITY, 0));
		}

		/* Return 'nil' if there is no data and the channel can't receive more data */
		if (!len) {
			lua_pushnil(L);
			return -1;
		}

		/* Otherwise, return all data */
		len = output + input - offset;
	}

  dup:
	_hlua_channel_dup(chn, L, offset, len);
	return 1;
}

/* Copies the first line (including the trailing LF) of input data in the
 * channel's buffer. It is possible to set a specific offset (0 by default) and
 * a length (all remaining input data starting for the offset by default). If
 * there is not enough input data and more data can be received, the function
 * yields. If a length is explicitly specified, no more data are
 * copied. Otherwise, if no LF is found and more data can be received, this
 * function yields.
 *
 * From an action, All input data are considered. For a filter, the offset and
 * the length of input data to consider are retrieved from the filter context.
 */
__LJMP static int hlua_channel_get_line_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	struct filter *filter;
	size_t l, input, output;
	int offset, len;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	output = co_data(chn);
	input = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 1) {
		offset = MAY_LJMP(luaL_checkinteger(L, 2));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	len = output + input - offset;
	if (lua_gettop(L) == 3) {
		len = MAY_LJMP(luaL_checkinteger(L, 3));
		if (!len)
			goto dup;
		if (len == -1)
			len = global.tune.bufsize;
		if (len < 0) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	for (l = 0; l < len; l++) {
		if (l + offset >= output + input)
			break;
		if (*(b_peek(&chn->buf, offset + l)) == '\n') {
			len = l+1;
			goto dup;
		}
	}

	/* Wait for more data if possible if no line is found and no length was
	 * specified or not enough data was received.
	 */
	if (lua_gettop(L) != 3 ||  offset + len > output + input) {
		if (!HLUA_CANT_YIELD(hlua_gethlua(L)) && !channel_input_closed(chn) && channel_may_recv(chn)) {
			/* Yield waiting for more data */
			MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_get_line_yield, TICK_ETERNITY, 0));
		}

		/* Return 'nil' if there is no data and the channel can't receive more data */
		if (!len) {
			lua_pushnil(L);
			return -1;
		}

		/* Otherwise, return all data */
		len = output + input - offset;
	}

  dup:
	_hlua_channel_dup(chn, L, offset, len);
	return 1;
}

/* [ DEPRECATED ]
 *
 * Duplicate all input data foud in the channel's buffer. The data are not
 * removed from the buffer. This function relies on _hlua_channel_dup().
 *
 * From an action, All input data are considered. For a filter, the offset and
 * the length of input data to consider are retrieved from the filter context.
 */
__LJMP static int hlua_channel_dup(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	size_t offset, len;

	MAY_LJMP(check_args(L, 1, "dup"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	if (!ci_data(chn) && channel_input_closed(chn)) {
		lua_pushnil(L);
		return 1;
	}

	_hlua_channel_dup(chn, L, offset, len);
	return 1;
}

/* [ DEPRECATED ]
 *
 * Get all input data foud in the channel's buffer. The data are removed from
 * the buffer after the copy. This function relies on _hlua_channel_dup() and
 * _hlua_channel_delete().
 *
 * From an action, All input data are considered. For a filter, the offset and
 * the length of input data to consider are retrieved from the filter context.
 */
__LJMP static int hlua_channel_get(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	size_t offset, len;
	int ret;

	MAY_LJMP(check_args(L, 1, "get"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	if (!ci_data(chn) && channel_input_closed(chn)) {
		lua_pushnil(L);
		return 1;
	}

	ret = _hlua_channel_dup(chn, L, offset, len);
	_hlua_channel_delete(chn, offset, ret);
	return 1;
}

/* This functions consumes and returns one line. If the channel is closed,
 * and the last data does not contains a final '\n', the data are returned
 * without the final '\n'. When no more data are available, it returns nil
 * value.
 *
 * From an action, All input data are considered. For a filter, the offset and
 * the length of input data to consider are retrieved from the filter context.
 */
__LJMP static int hlua_channel_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	struct filter *filter;
	size_t l, offset, len;
	int ret;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	if (!ci_data(chn) && channel_input_closed(chn)) {
		lua_pushnil(L);
		return 1;
	}

	for (l = 0; l < len; l++) {
		if (*(b_peek(&chn->buf, offset+l)) == '\n') {
			len = l+1;
			goto dup;
		}
	}

	if (!HLUA_CANT_YIELD(hlua_gethlua(L)) && !channel_input_closed(chn) && channel_may_recv(chn)) {
		/* Yield waiting for more data */
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_getline_yield, TICK_ETERNITY, 0));
	}

  dup:
	ret = _hlua_channel_dup(chn, L, offset, len);
	_hlua_channel_delete(chn, offset, ret);
	return 1;
}

/* [ DEPRECATED ]
 *
 * Check arguments for the function "hlua_channel_getline_yield".
 */
__LJMP static int hlua_channel_getline(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 1, "getline"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}
	return MAY_LJMP(hlua_channel_getline_yield(L, 0, 0));
}

/* Retrieves a given amount of input data at the given offset. By default all
 * available input data are returned. The offset may be negactive to start from
 * the end of input data. The length may be -1 to set it to the maximum buffer
 * size.
 */
__LJMP static int hlua_channel_get_data(lua_State *L)
{
	struct channel *chn;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'data' expects at most 2 arguments"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}
	return MAY_LJMP(hlua_channel_get_data_yield(L, 0, 0));
}

/* Retrieves a given amount of input data at the given offset. By default all
 * available input data are returned. The offset may be negactive to start from
 * the end of input data. The length may be -1 to set it to the maximum buffer
 * size.
 */
__LJMP static int hlua_channel_get_line(lua_State *L)
{
	struct channel *chn;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'line' expects at most 2 arguments"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}
	return MAY_LJMP(hlua_channel_get_line_yield(L, 0, 0));
}

/* Appends a string into the input side of channel. It returns the length of the
 * written string, or -1 if the channel is closed or if the buffer size is too
 * little for the data. 0 may be returned if nothing is copied. This function
 * does not yield.
 *
 * For a filter, the context is updated on success.
 */
__LJMP static int hlua_channel_append(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	const char *str;
	size_t sz, offset, len;
	int ret;

	MAY_LJMP(check_args(L, 2, "append"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	ret = _hlua_channel_insert(chn, L, ist2(str, sz), offset);
	if (ret > 0 && filter) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		flt_update_offsets(filter, chn, ret);
		flt_ctx->cur_len[CHN_IDX(chn)] += ret;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/* Prepends a string into the input side of channel. It returns the length of the
 * written string, or -1 if the channel is closed or if the buffer size is too
 * little for the data. 0 may be returned if nothing is copied. This function
 * does not yield.
 *
 * For a filter, the context is updated on success.
 */
__LJMP static int hlua_channel_prepend(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	const char *str;
	size_t sz, offset, len;
	int ret;

	MAY_LJMP(check_args(L, 2, "prepend"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	ret = _hlua_channel_insert(chn, L, ist2(str, sz), offset);
	if (ret > 0 && filter) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		flt_update_offsets(filter, chn, ret);
		flt_ctx->cur_len[CHN_IDX(chn)] += ret;
	}

	lua_pushinteger(L, ret);
	return 1;
}

/* Inserts a given amount of input data at the given offset by a string
 * content. By default the string is appended in front of input data. It
 * returns the length of the written string, or -1 if the channel is closed or
 * if the buffer size is too little for the data.
 *
 * For a filter, the context is updated on success.
 */
__LJMP static int hlua_channel_insert_data(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	const char *str;
	size_t sz, input, output;
	int ret, offset;

	if (lua_gettop(L) < 2 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'insert' expects at least 1 argument and at most 2 arguments"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));

	output = co_data(chn);
	input = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 2) {
		offset = MAY_LJMP(luaL_checkinteger(L, 3));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset > output + input) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	ret = _hlua_channel_insert(chn, L, ist2(str, sz), offset);
	if (ret > 0 && filter) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		flt_update_offsets(filter, chn, ret);
		flt_ctx->cur_len[CHN_IDX(chn)] += ret;
	}

	lua_pushinteger(L, ret);
	return 1;
}
/* Replaces a given amount of input data at the given offset by a string
 * content. By default all remaining data are removed (offset = 0 and len =
 * -1). It returns the length of the written string, or -1 if the channel is
 * closed or if the buffer size is too little for the data.
 *
 * For a filter, the context is updated on success.
 */
__LJMP static int hlua_channel_set_data(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	const char *str;
	size_t sz, input, output;
	int ret, offset, len;

	if (lua_gettop(L) < 2 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set' expects at least 1 argument and at most 3 arguments"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));

	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	output = co_data(chn);
	input = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 2) {
		offset = MAY_LJMP(luaL_checkinteger(L, 3));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	len = output + input - offset;
	if (lua_gettop(L) == 4) {
		len = MAY_LJMP(luaL_checkinteger(L, 4));
		if (!len)
			goto set;
		if (len == -1)
			len = output + input - offset;
		if (len < 0 || offset + len > output + input) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

  set:
	/* Be sure we can copied the string once input data will be removed. */
	if (sz > c_room(chn) + len)
		lua_pushinteger(L, -1);
	else {
		_hlua_channel_delete(chn, offset, len);
		ret = _hlua_channel_insert(chn, L, ist2(str, sz), offset);
		if (filter) {
			struct hlua_flt_ctx *flt_ctx = filter->ctx;

			len -= (ret > 0 ? ret : 0);
			flt_update_offsets(filter, chn, -len);
			flt_ctx->cur_len[CHN_IDX(chn)] -= len;
		}

		lua_pushinteger(L, ret);
	}
	return 1;
}

/* Removes a given amount of input data at the given offset. By default all
 * input data are removed (offset = 0 and len = -1). It returns the amount of
 * the removed data.
 *
 * For a filter, the context is updated on success.
 */
__LJMP static int hlua_channel_del_data(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	size_t input, output;
	int offset, len;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'remove' expects at most 2 arguments"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	output = co_data(chn);
	input = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 1) {
		offset = MAY_LJMP(luaL_checkinteger(L, 2));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	len = output + input - offset;
	if (lua_gettop(L) == 3) {
		len = MAY_LJMP(luaL_checkinteger(L, 3));
		if (!len)
			goto end;
		if (len == -1)
			len = output + input - offset;
		if (len < 0 || offset + len > output + input) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	_hlua_channel_delete(chn, offset, len);
	if (filter) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		flt_update_offsets(filter, chn, -len);
		flt_ctx->cur_len[CHN_IDX(chn)] -= len;
	}

  end:
	lua_pushinteger(L, len);
	return 1;
}

/* Append data in the output side of the buffer. This data is immediately
 * sent. The function returns the amount of data written. If the buffer
 * cannot contain the data, the function yields. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_channel_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	struct filter *filter;
	const char *str;
	size_t offset, len, sz;
	int l, ret;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	l = MAY_LJMP(luaL_checkinteger(L, 3));

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));


	if (unlikely(channel_output_closed(chn))) {
		lua_pushinteger(L, -1);
		return 1;
	}

	len = c_room(chn);
	if (len > sz -l) {
		if (filter) {
			lua_pushinteger(L, -1);
			return 1;
		}
		len = sz - l;
	}

	ret = _hlua_channel_insert(chn, L, ist2(str, len), offset);
	if (ret == -1) {
		lua_pop(L, 1);
		lua_pushinteger(L, -1);
		return 1;
	}
	if (ret) {
		if (filter) {
			struct hlua_flt_ctx *flt_ctx = filter->ctx;


			flt_update_offsets(filter, chn, ret);
			FLT_OFF(filter, chn) += ret;
			flt_ctx->cur_off[CHN_IDX(chn)] += ret;
		}
		else
			c_adv(chn, ret);

		l += ret;
		lua_pop(L, 1);
		lua_pushinteger(L, l);
	}

	if (l < sz) {
		/* Yield only if the channel's output is not empty.
		 * Otherwise it means we cannot add more data. */
		if (co_data(chn) == 0 || HLUA_CANT_YIELD(hlua_gethlua(L)))
			return 1;

		/* If we are waiting for space in the response buffer, we
		 * must set the flag WAKERESWR. This flag required the task
		 * wake up if any activity is detected on the response buffer.
		 */
		if (chn->flags & CF_ISRESP)
			HLUA_SET_WAKERESWR(hlua);
		else
			HLUA_SET_WAKEREQWR(hlua);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just a wrapper of "_hlua_channel_send". This wrapper permits
 * yield the LUA process, and resume it without checking the
 * input arguments.
 *
 * This function cannot be called from a filter.
 */
__LJMP static int hlua_channel_send(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "send"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}
	lua_pushinteger(L, 0);
	return MAY_LJMP(hlua_channel_send_yield(L, 0, 0));
}

/* This function forward and amount of butes. The data pass from
 * the input side of the buffer to the output side, and can be
 * forwarded. This function never fails.
 *
 * The Lua function takes an amount of bytes to be forwarded in
 * input. It returns the number of bytes forwarded.
 */
__LJMP static int hlua_channel_forward_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	struct filter *filter;
	size_t offset, len, fwd;
	int l, max;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	fwd = MAY_LJMP(luaL_checkinteger(L, 2));
	l = MAY_LJMP(luaL_checkinteger(L, -1));

	offset = co_data(chn);
	len = ci_data(chn);

	filter = hlua_channel_filter(L, 1, chn, &offset, &len);
	if (filter && !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	max = fwd - l;
	if (max > len)
		max = len;

	if (filter) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		FLT_OFF(filter, chn) += max;
		flt_ctx->cur_off[CHN_IDX(chn)] += max;
		flt_ctx->cur_len[CHN_IDX(chn)] -= max;
	}
	else
		channel_forward(chn, max);

	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* Check if it miss bytes to forward. */
	if (l < fwd) {
		/* The the input channel or the output channel are closed, we
		 * must return the amount of data forwarded.
		 */
		if (channel_input_closed(chn) || channel_output_closed(chn) ||  HLUA_CANT_YIELD(hlua_gethlua(L)))
			return 1;

		/* If we are waiting for space data in the response buffer, we
		 * must set the flag WAKERESWR. This flag required the task
		 * wake up if any activity is detected on the response buffer.
		 */
		if (chn->flags & CF_ISRESP)
			HLUA_SET_WAKERESWR(hlua);
		else
			HLUA_SET_WAKEREQWR(hlua);

		/* Otherwise, we can yield waiting for new data in the input side. */
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_forward_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just check the input and prepare the stack for the previous
 * function "hlua_channel_forward_yield"
 *
 * This function cannot be called from a filter.
 */
__LJMP static int hlua_channel_forward(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "forward"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}
	lua_pushinteger(L, 0);
	return MAY_LJMP(hlua_channel_forward_yield(L, 0, 0));
}

/* Just returns the number of bytes available in the input
 * side of the buffer. This function never fails.
 */
__LJMP static int hlua_channel_get_in_len(lua_State *L)
{
	struct channel *chn;
	struct filter *filter;
	size_t output, input;

	MAY_LJMP(check_args(L, 1, "input"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	output = co_data(chn);
	input = ci_data(chn);
	filter = hlua_channel_filter(L, 1, chn, &output, &input);
	if (filter || !IS_HTX_STRM(chn_strm(chn)))
		lua_pushinteger(L, input);
	else {
		struct htx *htx = htxbuf(&chn->buf);

		lua_pushinteger(L, htx->data - co_data(chn));
	}
	return 1;
}

/* Returns true if the channel is full. */
__LJMP static int hlua_channel_is_full(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 1, "is_full"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	/* ignore the reserve, we are not on a producer side (ie in an
	 * applet).
	 */
	lua_pushboolean(L, channel_full(chn, 0));
	return 1;
}

/* Returns true if the channel may still receive data. */
__LJMP static int hlua_channel_may_recv(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 1, "may_recv"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushboolean(L, (!channel_input_closed(chn) && channel_may_recv(chn)));
	return 1;
}

/* Returns true if the channel is the response channel. */
__LJMP static int hlua_channel_is_resp(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 1, "is_resp"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	lua_pushboolean(L, !!(chn->flags & CF_ISRESP));
	return 1;
}

/* Just returns the number of bytes available in the output
 * side of the buffer. This function never fails.
 */
__LJMP static int hlua_channel_get_out_len(lua_State *L)
{
	struct channel *chn;
	size_t output, input;

	MAY_LJMP(check_args(L, 1, "output"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	output = co_data(chn);
	input = ci_data(chn);
	hlua_channel_filter(L, 1, chn, &output, &input);

	lua_pushinteger(L, output);
	return 1;
}

/*
 *
 *
 * Class Fetches
 *
 *
 */

/* Returns a struct hlua_session if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_smp *hlua_checkfetches(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_fetches_ref));
}

/* This function creates and push in the stack a fetch object according
 * with a current TXN.
 */
__LJMP static int hlua_fetches_new(lua_State *L, struct hlua_txn *txn, unsigned int flags)
{
	struct hlua_smp *hsmp;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Fetches object is the
	 * transaction object.
	 */
	lua_newtable(L);
	hsmp = lua_newuserdata(L, sizeof(*hsmp));
	lua_rawseti(L, -2, 0);

	hsmp->s = txn->s;
	hsmp->p = txn->p;
	hsmp->dir = txn->dir;
	hsmp->flags = flags;

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_fetches_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function is an LUA binding. It is called with each sample-fetch.
 * It uses closure argument to store the associated sample-fetch. It
 * returns only one argument or throws an error. An error is thrown
 * only if an error is encountered during the argument parsing. If
 * the "sample-fetch" function fails, nil is returned.
 */
__LJMP static int hlua_run_sample_fetch(lua_State *L)
{
	struct hlua_smp *hsmp;
	struct sample_fetch *f;
	struct arg args[ARGM_NBARGS + 1] = {{0}};
	int i;
	struct sample smp;

	/* Get closure arguments. */
	f = lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditional arguments. */
	hsmp = MAY_LJMP(hlua_checkfetches(L, 1));

	/* Check execution authorization. */
	if (f->use & SMP_USE_HTTP_ANY &&
	    !(hsmp->flags & HLUA_F_MAY_USE_HTTP)) {
		lua_pushfstring(L, "the sample-fetch '%s' needs an HTTP parser which "
		                   "is not available in Lua services", f->kw);
		WILL_LJMP(lua_error(L));
	}

	/* Get extra arguments. */
	for (i = 0; i < lua_gettop(L) - 1; i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 2, &args[i]);
	}
	args[i].type = ARGT_STOP;
	args[i].data.str.area = NULL;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 2, args, f->arg_mask, hsmp->p));

	/* Run the special args checker. */
	if (f->val_args && !f->val_args(args, NULL)) {
		hlua_pushfstring_safe(L, "error in arguments");
		goto error;
	}

	/* Initialise the sample. */
	memset(&smp, 0, sizeof(smp));

	/* Run the sample fetch process. */
	smp_set_owner(&smp, hsmp->p, hsmp->s->sess, hsmp->s, hsmp->dir & SMP_OPT_DIR);
	if (!f->process(args, &smp, f->kw, f->private)) {
		if (hsmp->flags & HLUA_F_AS_STRING)
			lua_pushstring(L, "");
		else
			lua_pushnil(L);
		goto end;
	}

	/* Convert the returned sample in lua value. */
	if (hsmp->flags & HLUA_F_AS_STRING)
		MAY_LJMP(hlua_smp2lua_str(L, &smp));
	else
		MAY_LJMP(hlua_smp2lua(L, &smp));

  end:
	free_args(args);
	return 1;

  error:
	free_args(args);
	WILL_LJMP(lua_error(L));
	return 0; /* Never reached */
}

/*
 *
 *
 * Class Converters
 *
 *
 */

/* Returns a struct hlua_session if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_smp *hlua_checkconverters(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_converters_ref));
}

/* This function creates and push in the stack a Converters object
 * according with a current TXN.
 */
__LJMP static int hlua_converters_new(lua_State *L, struct hlua_txn *txn, unsigned int flags)
{
	struct hlua_smp *hsmp;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	hsmp = lua_newuserdata(L, sizeof(*hsmp));
	lua_rawseti(L, -2, 0);

	hsmp->s = txn->s;
	hsmp->p = txn->p;
	hsmp->dir = txn->dir;
	hsmp->flags = flags;

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_converters_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function is an LUA binding. It is called with each converter.
 * It uses closure argument to store the associated converter. It
 * returns only one argument or throws an error. An error is thrown
 * only if an error is encountered during the argument parsing. If
 * the converter function function fails, nil is returned.
 */
__LJMP static int hlua_run_sample_conv(lua_State *L)
{
	struct hlua_smp *hsmp;
	struct sample_conv *conv;
	struct arg args[ARGM_NBARGS + 1] = {{0}};
	int i;
	struct sample smp;

	/* Get closure arguments. */
	conv = lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditional arguments. */
	hsmp = MAY_LJMP(hlua_checkconverters(L, 1));

	/* Get extra arguments. */
	for (i = 0; i < lua_gettop(L) - 2; i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 3, &args[i]);
	}
	args[i].type = ARGT_STOP;
	args[i].data.str.area = NULL;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 3, args, conv->arg_mask, hsmp->p));

	/* Run the special args checker. */
	if (conv->val_args && !conv->val_args(args, conv, "", 0, NULL)) {
		hlua_pusherror(L, "error in arguments");
		goto error;
	}

	/* Initialise the sample. */
	memset(&smp, 0, sizeof(smp));
	if (!hlua_lua2smp(L, 2, &smp)) {
		hlua_pusherror(L, "error in the input argument");
		goto error;
	}

	smp_set_owner(&smp, hsmp->p, hsmp->s->sess, hsmp->s, hsmp->dir & SMP_OPT_DIR);

	/* Apply expected cast. */
	if (!sample_casts[smp.data.type][conv->in_type]) {
		hlua_pusherror(L, "invalid input argument: cannot cast '%s' to '%s'",
		               smp_to_type[smp.data.type], smp_to_type[conv->in_type]);
		goto error;
	}
	if (sample_casts[smp.data.type][conv->in_type] != c_none &&
	    !sample_casts[smp.data.type][conv->in_type](&smp)) {
		hlua_pusherror(L, "error during the input argument casting");
		goto error;
	}

	/* Run the sample conversion process. */
	if (!conv->process(args, &smp, conv->private)) {
		if (hsmp->flags & HLUA_F_AS_STRING)
			lua_pushstring(L, "");
		else
			lua_pushnil(L);
		goto end;
	}

	/* Convert the returned sample in lua value. */
	if (hsmp->flags & HLUA_F_AS_STRING)
		MAY_LJMP(hlua_smp2lua_str(L, &smp));
	else
		MAY_LJMP(hlua_smp2lua(L, &smp));
  end:
	free_args(args);
	return 1;

  error:
	free_args(args);
	WILL_LJMP(lua_error(L));
	return 0; /* Never reached */
}

/*
 *
 *
 * Class AppletTCP
 *
 *
 */

/* Returns a struct hlua_txn if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_appctx *hlua_checkapplet_tcp(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_applet_tcp_ref));
}

/* This function creates and push in the stack an Applet object
 * according with a current TXN.
 */
static int hlua_applet_tcp_new(lua_State *L, struct appctx *ctx)
{
	struct hlua_appctx *luactx;
	struct stream *s = appctx_strm(ctx);
	struct proxy *p;

	ALREADY_CHECKED(s);
	p = s->be;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	luactx = lua_newuserdata(L, sizeof(*luactx));
	lua_rawseti(L, -2, 0);
	luactx->appctx = ctx;
	luactx->htxn.s = s;
	luactx->htxn.p = p;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, &luactx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, &luactx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, &luactx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, &luactx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_applet_tcp_ref);
	lua_setmetatable(L, -2);

	return 1;
}

__LJMP static int hlua_applet_tcp_set_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set_var' needs between 3 and 4 arguments"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	/* Converts the third argument in a sample. */
	memset(&smp, 0, sizeof(smp));
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. We don't need to dup the smp, vars API
	 * already takes care of duplicating dynamic var data.
	 */
	smp_set_owner(&smp, s->be, s->sess, s, 0);

	if (lua_gettop(L) == 4 && lua_toboolean(L, 4))
		lua_pushboolean(L, vars_set_by_name_ifexist(name, len, &smp) != 0);
	else
		lua_pushboolean(L, vars_set_by_name(name, len, &smp) != 0);

	return 1;
}

__LJMP static int hlua_applet_tcp_unset_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "unset_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	/* Unset the variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);
	lua_pushboolean(L, vars_unset_by_name_ifexist(name, len, &smp) != 0);
	return 1;
}

__LJMP static int hlua_applet_tcp_get_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "get_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	smp_set_owner(&smp, s->be, s->sess, s, 0);
	if (!vars_get_by_name(name, len, &smp, NULL)) {
		lua_pushnil(L);
		return 1;
	}

	return MAY_LJMP(hlua_smp2lua(L, &smp));
}

__LJMP static int hlua_applet_tcp_set_priv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct hlua_cli_ctx *cli_ctx = luactx->appctx->svcctx;
	struct stream *s = luactx->htxn.s;
	struct hlua *hlua = hlua_stream_ctx_get(s, cli_ctx->hlua->state_id);

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!hlua)
		return 0;

	MAY_LJMP(check_args(L, 2, "set_priv"));

	/* Remove previous value. */
	luaL_unref(L, LUA_REGISTRYINDEX, hlua->Mref);

	/* Get and store new value. */
	lua_pushvalue(L, 2); /* Copy the element 2 at the top of the stack. */
	hlua->Mref = luaL_ref(L, LUA_REGISTRYINDEX); /* pop the previously pushed value. */

	return 0;
}

__LJMP static int hlua_applet_tcp_get_priv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct hlua_cli_ctx *cli_ctx = luactx->appctx->svcctx;
	struct stream *s = luactx->htxn.s;
	struct hlua *hlua = hlua_stream_ctx_get(s, cli_ctx->hlua->state_id);

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_tcp_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	int ret;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;

	/* Read the maximum amount of data available. */
	ret = co_getline_nc(sc_oc(sc), &blk1, &len1, &blk2, &len2);

	/* Data not yet available. return yield. */
	if (ret == 0) {
		applet_need_more_data(luactx->appctx);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_getline_yield, TICK_ETERNITY, 0));
	}

	/* End of data: commit the total strings and return. */
	if (ret < 0) {
		luaL_pushresult(&luactx->b);
		return 1;
	}

	/* Ensure that the block 2 length is usable. */
	if (ret == 1)
		len2 = 0;

	/* don't check the max length read and don't check. */
	luaL_addlstring(&luactx->b, blk1, len1);
	luaL_addlstring(&luactx->b, blk2, len2);

	/* Consume input channel output buffer data. */
	co_skip(sc_oc(sc), len1 + len2);
	luaL_pushresult(&luactx->b);
	return 1;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_tcp_getline(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));

	/* Initialise the string catenation. */
	luaL_buffinit(L, &luactx->b);

	return MAY_LJMP(hlua_applet_tcp_getline_yield(L, 0, 0));
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_tcp_recv_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	size_t len = MAY_LJMP(luaL_checkinteger(L, 2));
	int ret;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;

	/* Read the maximum amount of data available. */
	if (luactx->appctx->flags & APPCTX_FL_INOUT_BUFS)
		ret = b_getblk_nc(&luactx->appctx->inbuf, &blk1, &len1, &blk2, &len2, 0, b_data(&luactx->appctx->inbuf));
	else
		ret = co_getblk_nc(sc_oc(sc), &blk1, &len1, &blk2, &len2);

	/* Data not yet available. return yield. */
	if (ret == 0) {
		applet_need_more_data(luactx->appctx);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));
	}

	/* End of data: commit the total strings and return. */
	if (ret < 0) {
		luaL_pushresult(&luactx->b);
		return 1;
	}

	/* Ensure that the block 2 length is usable. */
	if (ret == 1)
		len2 = 0;

	if (len == -1) {

		/* If len == -1, catenate all the data avalaile and
		 * yield because we want to get all the data until
		 * the end of data stream.
		 */
		luaL_addlstring(&luactx->b, blk1, len1);
		luaL_addlstring(&luactx->b, blk2, len2);
		if (luactx->appctx->flags & APPCTX_FL_INOUT_BUFS)
			b_del(&luactx->appctx->inbuf, len1 + len2);
		else
			co_skip(sc_oc(sc), len1 + len2);
		applet_need_more_data(luactx->appctx);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));

	} else {

		/* Copy the first block caping to the length required. */
		if (len1 > len)
			len1 = len;
		luaL_addlstring(&luactx->b, blk1, len1);
		len -= len1;

		/* Copy the second block. */
		if (len2 > len)
			len2 = len;
		luaL_addlstring(&luactx->b, blk2, len2);
		len -= len2;

		if (luactx->appctx->flags & APPCTX_FL_INOUT_BUFS)
			b_del(&luactx->appctx->inbuf, len1 + len2);
		else
			co_skip(sc_oc(sc), len1 + len2);

		/* If there is no other data available, yield waiting for new data. */
		if (len > 0) {
			lua_pushinteger(L, len);
			lua_replace(L, 2);
			applet_need_more_data(luactx->appctx);
			MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));
		}

		/* return the result. */
		luaL_pushresult(&luactx->b);
		return 1;
	}

	/* we never execute this */
	hlua_pusherror(L, "Lua: internal error");
	WILL_LJMP(lua_error(L));
	return 0;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_tcp_recv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	int len = -1;

	if (lua_gettop(L) > 2)
		WILL_LJMP(luaL_error(L, "The 'recv' function requires between 1 and 2 arguments."));
	if (lua_gettop(L) >= 2) {
		len = MAY_LJMP(luaL_checkinteger(L, 2));
		lua_pop(L, 1);
	}

	/* Confirm or set the required length */
	lua_pushinteger(L, len);

	/* Initialise the string catenation. */
	luaL_buffinit(L, &luactx->b);

	return MAY_LJMP(hlua_applet_tcp_recv_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediately
 * sent. The function returns the amount of data written. If the buffer
 * cannot contain the data, the function yields. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_applet_tcp_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	size_t len;
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *chn = sc_ic(sc);
	int max;

	/* Get the max amount of data which can be written */
	if (luactx->appctx->flags & APPCTX_FL_INOUT_BUFS)
		max = b_room(&luactx->appctx->outbuf);
	else
		max = channel_recv_max(chn);

	if (max > (len - l))
		max = len - l;

	/* Copy data. */
	applet_putblk(luactx->appctx, str + l, max);

	/* update counters. */
	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If some data is not send, declares the situation to the
	 * applet, and returns a yield.
	 */
	if (l < len) {
		if (luactx->appctx->flags & APPCTX_FL_INOUT_BUFS)
			applet_have_more_data(luactx->appctx);
		else
			sc_need_room(sc, channel_recv_max(chn) + 1);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_send_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just a wrapper of "hlua_applet_tcp_send_yield". This wrapper permits
 * yield the LUA process, and resume it without checking the
 * input arguments.
 */
__LJMP static int hlua_applet_tcp_send(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "send"));
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_applet_tcp_send_yield(L, 0, 0));
}

/*
 *
 *
 * Class AppletHTTP
 *
 *
 */

/* Returns a struct hlua_txn if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_appctx *hlua_checkapplet_http(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_applet_http_ref));
}

/* This function creates and push in the stack an Applet object
 * according with a current TXN.
 * It relies on the caller to have already reserved the room in ctx->svcctx
 * for the local storage of hlua_http_ctx.
 */
static int hlua_applet_http_new(lua_State *L, struct appctx *ctx)
{
	struct hlua_http_ctx *http_ctx = ctx->svcctx;
	struct hlua_appctx *luactx;
	struct hlua_txn htxn;
	struct stream *s = appctx_strm(ctx);
	struct proxy *px = s->be;
	struct htx *htx;
	struct htx_blk *blk;
	struct htx_sl *sl;
	struct ist path;
	unsigned long long len = 0;
	int32_t pos;
	struct http_uri_parser parser;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	luactx = lua_newuserdata(L, sizeof(*luactx));
	lua_rawseti(L, -2, 0);
	luactx->appctx = ctx;
	http_ctx->status = 200; /* Default status code returned. */
	http_ctx->reason = NULL; /* Use default reason based on status */
	luactx->htxn.s = s;
	luactx->htxn.p = px;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, &luactx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, &luactx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, &luactx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, &luactx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	htx = htxbuf(&s->req.buf);
	blk = htx_get_first_blk(htx);
	BUG_ON(!blk || htx_get_blk_type(blk) != HTX_BLK_REQ_SL);
	sl = htx_get_blk_ptr(htx, blk);

	/* Stores the request method. */
	lua_pushstring(L, "method");
	lua_pushlstring(L, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl));
	lua_settable(L, -3);

	/* Stores the http version. */
	lua_pushstring(L, "version");
	lua_pushlstring(L, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl));
	lua_settable(L, -3);

	/* creates an array of headers. hlua_http_get_headers() crates and push
	 * the array on the top of the stack.
	 */
	lua_pushstring(L, "headers");
	htxn.s = s;
	htxn.p = px;
	htxn.dir = SMP_OPT_DIR_REQ;
	if (!hlua_http_get_headers(L, &htxn.s->txn->req))
		return 0;
	lua_settable(L, -3);

	parser = http_uri_parser_init(htx_sl_req_uri(sl));
	path = http_parse_path(&parser);
	if (isttest(path)) {
		char *p, *q, *end;

		p = path.ptr;
		end = istend(path);
		q = p;
		while (q < end && *q != '?')
			q++;

		/* Stores the request path. */
		lua_pushstring(L, "path");
		lua_pushlstring(L, p, q - p);
		lua_settable(L, -3);

		/* Stores the query string. */
		lua_pushstring(L, "qs");
		if (*q == '?')
			q++;
		lua_pushlstring(L, q, end - q);
		lua_settable(L, -3);
	}

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);

		if (type == HTX_BLK_TLR || type == HTX_BLK_EOT)
			break;
		if (type == HTX_BLK_DATA)
			len += htx_get_blksz(blk);
	}
	if (htx->extra != HTX_UNKOWN_PAYLOAD_LENGTH)
		len += htx->extra;

	/* Stores the request path. */
	lua_pushstring(L, "length");
	lua_pushinteger(L, len);
	lua_settable(L, -3);

	/* Create an empty array of HTTP request headers. */
	lua_pushstring(L, "response");
	lua_newtable(L);
	lua_settable(L, -3);

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_applet_http_ref);
	lua_setmetatable(L, -2);

	return 1;
}

__LJMP static int hlua_applet_http_set_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set_var' needs between 3 and 4 arguments"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	/* Converts the third argument in a sample. */
	memset(&smp, 0, sizeof(smp));
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. We don't need to dup the smp, vars API
	 * already takes care of duplicating dynamic var data.
	 */
	smp_set_owner(&smp, s->be, s->sess, s, 0);

	if (lua_gettop(L) == 4 && lua_toboolean(L, 4))
		lua_pushboolean(L, vars_set_by_name_ifexist(name, len, &smp) != 0);
	else
		lua_pushboolean(L, vars_set_by_name(name, len, &smp) != 0);

	return 1;
}

__LJMP static int hlua_applet_http_unset_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "unset_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	/* Unset the variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);
	lua_pushboolean(L, vars_unset_by_name_ifexist(name, len, &smp) != 0);
	return 1;
}

__LJMP static int hlua_applet_http_get_var(lua_State *L)
{
	struct hlua_appctx *luactx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "get_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = luactx->htxn.s;

	smp_set_owner(&smp, s->be, s->sess, s, 0);
	if (!vars_get_by_name(name, len, &smp, NULL)) {
		lua_pushnil(L);
		return 1;
	}

	return MAY_LJMP(hlua_smp2lua(L, &smp));
}

__LJMP static int hlua_applet_http_set_priv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct hlua_http_ctx *http_ctx = luactx->appctx->svcctx;
	struct stream *s = luactx->htxn.s;
	struct hlua *hlua = hlua_stream_ctx_get(s, http_ctx->hlua->state_id);

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!hlua)
		return 0;

	MAY_LJMP(check_args(L, 2, "set_priv"));

	/* Remove previous value. */
	luaL_unref(L, LUA_REGISTRYINDEX, hlua->Mref);

	/* Get and store new value. */
	lua_pushvalue(L, 2); /* Copy the element 2 at the top of the stack. */
	hlua->Mref = luaL_ref(L, LUA_REGISTRYINDEX); /* pop the previously pushed value. */

	return 0;
}

__LJMP static int hlua_applet_http_get_priv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct hlua_http_ctx *http_ctx = luactx->appctx->svcctx;
	struct stream *s = luactx->htxn.s;
	struct hlua *hlua = hlua_stream_ctx_get(s, http_ctx->hlua->state_id);

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_http_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *req = sc_oc(sc);
	struct htx *htx;
	struct htx_blk *blk;
	size_t count;
	int stop = 0;

	htx = htx_from_buf(&req->buf);
	count = co_data(req);
	blk = htx_get_first_blk(htx);

	while (count && !stop && blk) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		struct ist v;
		uint32_t vlen;
		char *nl;

		vlen = sz;
		if (vlen > count) {
			if (type != HTX_BLK_DATA)
				break;
			vlen = count;
		}

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v.len = vlen;
				nl = istchr(v, '\n');
				if (nl != NULL) {
					stop = 1;
					vlen = nl - v.ptr + 1;
				}
				luaL_addlstring(&luactx->b, v.ptr, vlen);
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOT:
				stop = 1;
				break;

			default:
				break;
		}

		c_rew(req, vlen);
		count -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(htx, blk);
		else {
			htx_cut_data_blk(htx, blk, vlen);
			break;
		}
	}

	/* The message was fully consumed and no more data are expected
	 * (EOM flag set).
	 */
	if (htx_is_empty(htx) && (sc_opposite(sc)->flags & SC_FL_EOI))
		stop = 1;

	htx_to_buf(htx, &req->buf);
	if (!stop) {
		applet_need_more_data(luactx->appctx);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_getline_yield, TICK_ETERNITY, 0));
	}

	/* return the result. */
	luaL_pushresult(&luactx->b);
	return 1;
}


/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_http_getline(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));

	/* Initialise the string catenation. */
	luaL_buffinit(L, &luactx->b);

	return MAY_LJMP(hlua_applet_http_getline_yield(L, 0, 0));
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_http_recv_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *req = sc_oc(sc);
	struct htx *htx;
	struct htx_blk *blk;
	size_t count;
	int len;

	htx = htx_from_buf(&req->buf);
	len = MAY_LJMP(luaL_checkinteger(L, 2));
	count = co_data(req);
	blk = htx_get_head_blk(htx);
	while (count && len && blk) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		struct ist v;
		uint32_t vlen;

		vlen = sz;
		if (len > 0 && vlen > len)
			vlen = len;
		if (vlen > count) {
			if (type != HTX_BLK_DATA)
				break;
			vlen = count;
		}

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				luaL_addlstring(&luactx->b, v.ptr, vlen);
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOT:
				len = 0;
				break;

			default:
				break;
		}

		c_rew(req, vlen);
		count -= vlen;
		if (len > 0)
			len -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(htx, blk);
		else {
			htx_cut_data_blk(htx, blk, vlen);
			break;
		}
	}

	/* The message was fully consumed and no more data are expected
	 * (EOM flag set).
	 */
	if (htx_is_empty(htx) && (sc_opposite(sc)->flags & SC_FL_EOI))
		len = 0;

	htx_to_buf(htx, &req->buf);

	/* If we are no other data available, yield waiting for new data. */
	if (len) {
		if (len > 0) {
			lua_pushinteger(L, len);
			lua_replace(L, 2);
		}
		applet_need_more_data(luactx->appctx);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_recv_yield, TICK_ETERNITY, 0));
	}

	/* return the result. */
	luaL_pushresult(&luactx->b);
	return 1;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_http_recv(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	int len = -1;

	/* Check arguments. */
	if (lua_gettop(L) > 2)
		WILL_LJMP(luaL_error(L, "The 'recv' function requires between 1 and 2 arguments."));
	if (lua_gettop(L) >= 2) {
		len = MAY_LJMP(luaL_checkinteger(L, 2));
		lua_pop(L, 1);
	}

	lua_pushinteger(L, len);

	/* Initialise the string catenation. */
	luaL_buffinit(L, &luactx->b);

	return MAY_LJMP(hlua_applet_http_recv_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediately
 * sent. The function returns the amount of data written. If the buffer
 * cannot contain the data, the function yields. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_applet_http_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *res = sc_ic(sc);
	struct htx *htx = htx_from_buf(&res->buf);
	const char *data;
	size_t len;
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int max;

	max = htx_get_max_blksz(htx, channel_htx_recv_max(res, htx));
	if (!max)
		goto snd_yield;

	data = MAY_LJMP(luaL_checklstring(L, 2, &len));

	/* Get the max amount of data which can write as input in the channel. */
	if (max > (len - l))
		max = len - l;

	/* Copy data. */
	max = htx_add_data(htx, ist2(data + l, max));
	channel_add_input(res, max);

	/* update counters. */
	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If some data is not send, declares the situation to the
	 * applet, and returns a yield.
	 */
	if (l < len) {
	  snd_yield:
		htx_to_buf(htx, &res->buf);
		sc_need_room(sc, channel_recv_max(res) + 1);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_send_yield, TICK_ETERNITY, 0));
	}

	htx_to_buf(htx, &res->buf);
	return 1;
}

/* Just a wrapper of "hlua_applet_send_yield". This wrapper permits
 * yield the LUA process, and resume it without checking the
 * input arguments.
 */
__LJMP static int hlua_applet_http_send(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct hlua_http_ctx *http_ctx = luactx->appctx->svcctx;

	/* We want to send some data. Headers must be sent. */
	if (!(http_ctx->flags & APPLET_HDR_SENT)) {
		hlua_pusherror(L, "Lua: 'send' you must call start_response() before sending data.");
		WILL_LJMP(lua_error(L));
	}

	/* This integer is used for followinf the amount of data sent. */
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_applet_http_send_yield(L, 0, 0));
}

__LJMP static int hlua_applet_http_addheader(lua_State *L)
{
	const char *name;
	int ret;

	MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checkstring(L, 2));
	MAY_LJMP(luaL_checkstring(L, 3));

	/* Push in the stack the "response" entry. */
	ret = lua_getfield(L, 1, "response");
	if (ret != LUA_TTABLE) {
		hlua_pusherror(L, "Lua: 'add_header' internal error: AppletHTTP['response'] "
		                  "is expected as an array. %s found", lua_typename(L, ret));
		WILL_LJMP(lua_error(L));
	}

	/* check if the header is already registered if it is not
	 * the case, register it.
	 */
	ret = lua_getfield(L, -1, name);
	if (ret == LUA_TNIL) {

		/* Entry not found. */
		lua_pop(L, 1); /* remove the nil. The "response" table is the top of the stack. */

		/* Insert the new header name in the array in the top of the stack.
		 * It left the new array in the top of the stack.
		 */
		lua_newtable(L);
		lua_pushvalue(L, 2);
		lua_pushvalue(L, -2);
		lua_settable(L, -4);

	} else if (ret != LUA_TTABLE) {

		/* corruption error. */
		hlua_pusherror(L, "Lua: 'add_header' internal error: AppletHTTP['response']['%s'] "
		                  "is expected as an array. %s found", name, lua_typename(L, ret));
		WILL_LJMP(lua_error(L));
	}

	/* Now the top of thestack is an array of values. We push
	 * the header value as new entry.
	 */
	lua_pushvalue(L, 3);
	ret = lua_rawlen(L, -2);
	lua_rawseti(L, -2, ret + 1);
	lua_pushboolean(L, 1);
	return 1;
}

__LJMP static int hlua_applet_http_status(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	int status = MAY_LJMP(luaL_checkinteger(L, 2));
	const char *reason = MAY_LJMP(luaL_optlstring(L, 3, NULL, NULL));
	struct hlua_http_ctx *http_ctx = luactx->appctx->svcctx;

	if (status < 100 || status > 599) {
		lua_pushboolean(L, 0);
		return 1;
	}

	http_ctx->status = status;
	http_ctx->reason = reason;
	lua_pushboolean(L, 1);
	return 1;
}


__LJMP static int hlua_applet_http_send_response(lua_State *L)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct hlua_http_ctx *http_ctx = luactx->appctx->svcctx;
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *res = sc_ic(sc);
	struct htx *htx;
	struct htx_sl *sl;
	struct h1m h1m;
	const char *status, *reason;
	const char *name, *value;
	size_t nlen, vlen;
        unsigned int flags;

	/* Send the message at once. */
	htx = htx_from_buf(&res->buf);
	h1m_init_res(&h1m);

	/* Use the same http version than the request. */
	status = ultoa_r(http_ctx->status, trash.area, trash.size);
	reason = http_ctx->reason;
	if (reason == NULL)
		reason = http_get_reason(http_ctx->status);
	if (http_ctx->flags & APPLET_HTTP11) {
		flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist(status), ist(reason));
	}
	else {
		flags = HTX_SL_F_IS_RESP;
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.0"), ist(status), ist(reason));
	}
	if (!sl) {
		hlua_pusherror(L, "Lua applet http '%s': Failed to create response.\n",
		               luactx->appctx->rule->arg.hlua_rule->fcn->name);
		WILL_LJMP(lua_error(L));
	}
	sl->info.res.status = http_ctx->status;

	/* Get the array associated to the field "response" in the object AppletHTTP. */
	if (lua_getfield(L, 1, "response") != LUA_TTABLE) {
		hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response'] missing.\n",
		               luactx->appctx->rule->arg.hlua_rule->fcn->name);
		WILL_LJMP(lua_error(L));
	}

	/* Browse the list of headers. */
	lua_pushnil(L);
	while(lua_next(L, -2) != 0) {
		/* We expect a string as -2. */
		if (lua_type(L, -2) != LUA_TSTRING) {
			hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response'][] element must be a string. got %s.\n",
				       luactx->appctx->rule->arg.hlua_rule->fcn->name,
			               lua_typename(L, lua_type(L, -2)));
			WILL_LJMP(lua_error(L));
		}
		name = lua_tolstring(L, -2, &nlen);

		/* We expect an array as -1. */
		if (lua_type(L, -1) != LUA_TTABLE) {
			hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response']['%s'] element must be an table. got %s.\n",
				       luactx->appctx->rule->arg.hlua_rule->fcn->name,
				       name,
			               lua_typename(L, lua_type(L, -1)));
			WILL_LJMP(lua_error(L));
		}

		/* Browse the table who is on the top of the stack. */
		lua_pushnil(L);
		while(lua_next(L, -2) != 0) {
			int id;

			/* We expect a number as -2. */
			if (lua_type(L, -2) != LUA_TNUMBER) {
				hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response']['%s'][] element must be a number. got %s.\n",
					       luactx->appctx->rule->arg.hlua_rule->fcn->name,
					       name,
				               lua_typename(L, lua_type(L, -2)));
				WILL_LJMP(lua_error(L));
			}
			id = lua_tointeger(L, -2);

			/* We expect a string as -2. */
			if (lua_type(L, -1) != LUA_TSTRING) {
				hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response']['%s'][%d] element must be a string. got %s.\n",
					       luactx->appctx->rule->arg.hlua_rule->fcn->name,
					       name, id,
				               lua_typename(L, lua_type(L, -1)));
				WILL_LJMP(lua_error(L));
			}
			value = lua_tolstring(L, -1, &vlen);

			/* Simple Protocol checks. */
			if (isteqi(ist2(name, nlen), ist("transfer-encoding"))) {
				int ret;

				ret = h1_parse_xfer_enc_header(&h1m, ist2(value, vlen));
				if (ret < 0) {
					hlua_pusherror(L, "Lua applet http '%s': Invalid '%s' header.\n",
						       luactx->appctx->rule->arg.hlua_rule->fcn->name,
						       name);
					WILL_LJMP(lua_error(L));
				}
				else if (ret == 0)
					goto next; /* Skip it */
			}
			else if (isteqi(ist2(name, nlen), ist("content-length"))) {
				struct ist v = ist2(value, vlen);
				int ret;

				ret = h1_parse_cont_len_header(&h1m, &v);
				if (ret < 0) {
					hlua_pusherror(L, "Lua applet http '%s': Invalid '%s' header.\n",
						       luactx->appctx->rule->arg.hlua_rule->fcn->name,
						       name);
					WILL_LJMP(lua_error(L));
				}
				else if (ret == 0)
					goto next; /* Skip it */
			}

			/* Add a new header */
			if (!htx_add_header(htx, ist2(name, nlen), ist2(value, vlen))) {
				hlua_pusherror(L, "Lua applet http '%s': Failed to add header '%s' in the response.\n",
					       luactx->appctx->rule->arg.hlua_rule->fcn->name,
					       name);
				WILL_LJMP(lua_error(L));
			}
		  next:
			/* Remove the array from the stack, and get next element with a remaining string. */
			lua_pop(L, 1);
		}

		/* Remove the array from the stack, and get next element with a remaining string. */
		lua_pop(L, 1);
	}

	if (h1m.flags & H1_MF_CHNK)
		h1m.flags &= ~H1_MF_CLEN;
	if (h1m.flags & (H1_MF_CLEN|H1_MF_CHNK))
		h1m.flags |= H1_MF_XFER_LEN;

	/* Uset HTX start-line flags */
	if (h1m.flags & H1_MF_XFER_ENC)
		flags |= HTX_SL_F_XFER_ENC;
	if (h1m.flags & H1_MF_XFER_LEN) {
		flags |= HTX_SL_F_XFER_LEN;
		if (h1m.flags & H1_MF_CHNK)
			flags |= HTX_SL_F_CHNK;
		else if (h1m.flags & H1_MF_CLEN)
			flags |= HTX_SL_F_CLEN;
		if (h1m.body_len == 0)
			flags |= HTX_SL_F_BODYLESS;
	}
	sl->flags |= flags;

	/* If we don't have a content-length set, and the HTTP version is 1.1
	 * and the status code implies the presence of a message body, we must
	 * announce a transfer encoding chunked. This is required by haproxy
	 * for the keepalive compliance. If the applet announces a transfer-encoding
	 * chunked itself, don't do anything.
	 */
	if ((flags & (HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN)) == HTX_SL_F_VER_11 &&
	    http_ctx->status >= 200 && http_ctx->status != 204 && http_ctx->status != 304) {
		/* Add a new header */
		sl->flags |= (HTX_SL_F_XFER_ENC|H1_MF_CHNK|H1_MF_XFER_LEN);
		if (!htx_add_header(htx, ist("transfer-encoding"), ist("chunked"))) {
			hlua_pusherror(L, "Lua applet http '%s': Failed to add header 'transfer-encoding' in the response.\n",
				       luactx->appctx->rule->arg.hlua_rule->fcn->name);
			WILL_LJMP(lua_error(L));
		}
	}

	/* Finalize headers. */
	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		hlua_pusherror(L, "Lua applet http '%s': Failed create the response.\n",
			       luactx->appctx->rule->arg.hlua_rule->fcn->name);
		WILL_LJMP(lua_error(L));
	}

	if (htx_used_space(htx) > b_size(&res->buf) - global.tune.maxrewrite) {
		b_reset(&res->buf);
		hlua_pusherror(L, "Lua: 'start_response': response header block too big");
		WILL_LJMP(lua_error(L));
	}

	htx_to_buf(htx, &res->buf);
	channel_add_input(res, htx->data);

	/* Headers sent, set the flag. */
	http_ctx->flags |= APPLET_HDR_SENT;
	return 0;

}
/* We will build the status line and the headers of the HTTP response.
 * We will try send at once if its not possible, we give back the hand
 * waiting for more room.
 */
__LJMP static int hlua_applet_http_start_response_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *luactx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stconn *sc = appctx_sc(luactx->appctx);
	struct channel *res = sc_ic(sc);

	if (co_data(res)) {
		sc_need_room(sc, -1);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_start_response_yield, TICK_ETERNITY, 0));
	}
	return MAY_LJMP(hlua_applet_http_send_response(L));
}


__LJMP static int hlua_applet_http_start_response(lua_State *L)
{
	return MAY_LJMP(hlua_applet_http_start_response_yield(L, 0, 0));
}

/*
 *
 *
 * Class HTTP
 *
 *
 */

/* Returns a struct hlua_txn if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_txn *hlua_checkhttp(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_http_ref));
}

/* This function creates and push in the stack a HTTP object
 * according with a current TXN.
 */
__LJMP static int hlua_http_new(lua_State *L, struct hlua_txn *txn)
{
	struct hlua_txn *htxn;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	htxn = lua_newuserdata(L, sizeof(*htxn));
	lua_rawseti(L, -2, 0);

	htxn->s = txn->s;
	htxn->p = txn->p;
	htxn->dir = txn->dir;
	htxn->flags = txn->flags;

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_http_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function creates and returns an array containing the status-line
 * elements. This function does not fails.
 */
__LJMP static int hlua_http_get_stline(lua_State *L, struct htx_sl *sl)
{
	/* Create the table. */
	lua_newtable(L);

	if (sl->flags & HTX_SL_F_IS_RESP) {
		lua_pushstring(L, "version");
		lua_pushlstring(L, HTX_SL_RES_VPTR(sl), HTX_SL_RES_VLEN(sl));
		lua_settable(L, -3);
		lua_pushstring(L, "code");
		lua_pushlstring(L, HTX_SL_RES_CPTR(sl), HTX_SL_RES_CLEN(sl));
		lua_settable(L, -3);
		lua_pushstring(L, "reason");
		lua_pushlstring(L, HTX_SL_RES_RPTR(sl), HTX_SL_RES_RLEN(sl));
		lua_settable(L, -3);
	}
	else {
		lua_pushstring(L, "method");
		lua_pushlstring(L, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl));
		lua_settable(L, -3);
		lua_pushstring(L, "uri");
		lua_pushlstring(L, HTX_SL_REQ_UPTR(sl), HTX_SL_REQ_ULEN(sl));
		lua_settable(L, -3);
		lua_pushstring(L, "version");
		lua_pushlstring(L, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl));
		lua_settable(L, -3);
	}
	return 1;
}

/* This function creates ans returns an array of HTTP headers.
 * This function does not fails. It is used as wrapper with the
 * 2 following functions.
 */
__LJMP static int hlua_http_get_headers(lua_State *L, struct http_msg *msg)
{
	struct htx *htx;
	int32_t pos;

	/* Create the table. */
	lua_newtable(L);


	htx = htxbuf(&msg->chn->buf);
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist n, v;
		int len;

		if (type == HTX_BLK_HDR) {
			n = htx_get_blk_name(htx,blk);
			v = htx_get_blk_value(htx, blk);
		}
		else if (type == HTX_BLK_EOH)
			break;
		else
			continue;

		/* Check for existing entry:
		 * assume that the table is on the top of the stack, and
		 * push the key in the stack, the function lua_gettable()
		 * perform the lookup.
		 */
		lua_pushlstring(L, n.ptr, n.len);
		lua_gettable(L, -2);

		switch (lua_type(L, -1)) {
			case LUA_TNIL:
				/* Table not found, create it. */
				lua_pop(L, 1); /* remove the nil value. */
				lua_pushlstring(L, n.ptr, n.len);  /* push the header name as key. */
				lua_newtable(L); /* create and push empty table. */
				lua_pushlstring(L, v.ptr, v.len); /* push header value. */
				lua_rawseti(L, -2, 0); /* index header value (pop it). */
				lua_rawset(L, -3); /* index new table with header name (pop the values). */
				break;

			case LUA_TTABLE:
				/* Entry found: push the value in the table. */
				len = lua_rawlen(L, -1);
				lua_pushlstring(L, v.ptr, v.len); /* push header value. */
				lua_rawseti(L, -2, len+1); /* index header value (pop it). */
				lua_pop(L, 1); /* remove the table (it is stored in the main table). */
				break;

			default:
				/* Other cases are errors. */
				hlua_pusherror(L, "internal error during the parsing of headers.");
				WILL_LJMP(lua_error(L));
		}
	}
	return 1;
}

__LJMP static int hlua_http_req_get_headers(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 1, "req_get_headers"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_get_headers(L, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_get_headers(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 1, "res_get_headers"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_get_headers(L, &htxn->s->txn->rsp);
}

/* This function replace full header, or just a value in
 * the request or in the response. It is a wrapper fir the
 * 4 following functions.
 */
__LJMP static inline int hlua_http_rep_hdr(lua_State *L, struct http_msg *msg, int full)
{
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));
	const char *reg = MAY_LJMP(luaL_checkstring(L, 3));
	const char *value = MAY_LJMP(luaL_checkstring(L, 4));
	struct htx *htx;
	struct my_regex *re;

	if (!(re = regex_comp(reg, 1, 1, NULL)))
		WILL_LJMP(luaL_argerror(L, 3, "invalid regex"));

	htx = htxbuf(&msg->chn->buf);
	http_replace_hdrs(chn_strm(msg->chn), htx, ist2(name, name_len), value, re, full);
	regex_free(re);
	return 0;
}

__LJMP static int hlua_http_req_rep_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "req_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return MAY_LJMP(hlua_http_rep_hdr(L, &htxn->s->txn->req, 1));
}

__LJMP static int hlua_http_res_rep_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "res_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return MAY_LJMP(hlua_http_rep_hdr(L, &htxn->s->txn->rsp, 1));
}

__LJMP static int hlua_http_req_rep_val(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "req_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return MAY_LJMP(hlua_http_rep_hdr(L, &htxn->s->txn->req, 0));
}

__LJMP static int hlua_http_res_rep_val(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "res_rep_val"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return MAY_LJMP(hlua_http_rep_hdr(L, &htxn->s->txn->rsp, 0));
}

/* This function deletes all the occurrences of an header.
 * It is a wrapper for the 2 following functions.
 */
__LJMP static inline int hlua_http_del_hdr(lua_State *L, struct http_msg *msg)
{
	size_t len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct http_hdr_ctx ctx;

	ctx.blk = NULL;
	while (http_find_header(htx, ist2(name, len), &ctx, 1))
		http_remove_header(htx, &ctx);
	return 0;
}

__LJMP static int hlua_http_req_del_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "req_del_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_del_hdr(L, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_del_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "res_del_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_del_hdr(L, &htxn->s->txn->rsp);
}

/* This function adds an header. It is a wrapper used by
 * the 2 following functions.
 */
__LJMP static inline int hlua_http_add_hdr(lua_State *L, struct http_msg *msg)
{
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));
	size_t value_len;
	const char *value = MAY_LJMP(luaL_checklstring(L, 3, &value_len));
	struct htx *htx = htxbuf(&msg->chn->buf);

	lua_pushboolean(L, http_add_header(htx, ist2(name, name_len),
					   ist2(value, value_len)));
	return 0;
}

__LJMP static int hlua_http_req_add_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "req_add_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_add_hdr(L, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_add_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "res_add_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	return hlua_http_add_hdr(L, &htxn->s->txn->rsp);
}

static int hlua_http_req_set_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "req_set_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	hlua_http_del_hdr(L, &htxn->s->txn->req);
	return hlua_http_add_hdr(L, &htxn->s->txn->req);
}

static int hlua_http_res_set_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "res_set_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	hlua_http_del_hdr(L, &htxn->s->txn->rsp);
	return hlua_http_add_hdr(L, &htxn->s->txn->rsp);
}

/* This function set the method. */
static int hlua_http_req_set_meth(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	lua_pushboolean(L, http_req_replace_stline(0, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the method. */
static int hlua_http_req_set_path(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	lua_pushboolean(L, http_req_replace_stline(1, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the query-string. */
static int hlua_http_req_set_query(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	/* Check length. */
	if (name_len > trash.size - 1) {
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Add the mark question as prefix. */
	chunk_reset(&trash);
	trash.area[trash.data++] = '?';
	memcpy(trash.area + trash.data, name, name_len);
	trash.data += name_len;

	lua_pushboolean(L,
			http_req_replace_stline(2, trash.area, trash.data, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the uri. */
static int hlua_http_req_set_uri(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if (htxn->dir != SMP_OPT_DIR_REQ || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	lua_pushboolean(L, http_req_replace_stline(3, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the response code & optionally reason. */
static int hlua_http_res_set_status(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	unsigned int code = MAY_LJMP(luaL_checkinteger(L, 2));
	const char *str = MAY_LJMP(luaL_optlstring(L, 3, NULL, NULL));
	const struct ist reason = ist2(str, (str ? strlen(str) : 0));

	if (htxn->dir != SMP_OPT_DIR_RES || !IS_HTX_STRM(htxn->s))
		WILL_LJMP(lua_error(L));

	http_res_set_status(code, reason, htxn->s);
	return 0;
}

/*
 *
 *
 * Class HTTPMessage
 *
 *
 */

/* Returns a struct http_msg if the stack entry "ud" is a class HTTPMessage,
 * otherwise it throws an error.
 */
__LJMP static struct http_msg *hlua_checkhttpmsg(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_http_msg_ref));
}

/* Creates and pushes on the stack a HTTP object according with a current TXN.
 */
static int hlua_http_msg_new(lua_State *L, struct http_msg *msg)
{
	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	lua_newtable(L);
	lua_pushlightuserdata(L, msg);
	lua_rawseti(L, -2, 0);

	/* Create the "channel" field that contains the request channel object. */
	lua_pushstring(L, "channel");
	if (!hlua_channel_new(L, msg->chn))
		return 0;
	lua_rawset(L, -3);

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_http_msg_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* Helper function returning a filter attached to the HTTP message at the
 * position <ud> in the stack, filling the current offset and length of the
 * filter. If no filter is attached, NULL is returned and <offset> and <len> are
 * filled with output and input length respectively.
 */
static struct filter *hlua_http_msg_filter(lua_State *L, int ud, struct http_msg *msg, size_t *offset, size_t *len)
{
	struct channel *chn = msg->chn;
	struct htx *htx = htxbuf(&chn->buf);
	struct filter *filter = NULL;

	*offset = co_data(msg->chn);
	*len    = htx->data - co_data(msg->chn);

	if (lua_getfield(L, ud, "__filter") == LUA_TLIGHTUSERDATA) {
		filter  = lua_touserdata (L, -1);
		if (msg->msg_state >= HTTP_MSG_DATA) {
			struct hlua_flt_ctx *flt_ctx = filter->ctx;

			*offset  = flt_ctx->cur_off[CHN_IDX(chn)];
			*len     = flt_ctx->cur_len[CHN_IDX(chn)];
		}
	}

	lua_pop(L, 1);
	return filter;
}

/* Returns true if the channel attached to the HTTP message is the response
 * channel.
 */
__LJMP static int hlua_http_msg_is_resp(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 1, "is_resp"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	lua_pushboolean(L, !!(msg->chn->flags & CF_ISRESP));
	return 1;
}

/* Returns an array containing the elements status-line of the HTTP message. It relies
 * on hlua_http_get_stline().
 */
__LJMP static int hlua_http_msg_get_stline(lua_State *L)
{
	struct http_msg *msg;
	struct htx *htx;
	struct htx_sl *sl;

	MAY_LJMP(check_args(L, 1, "get_stline"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	htx = htxbuf(&msg->chn->buf);
	sl = http_get_stline(htx);
	if (!sl)
		return 0;
	return hlua_http_get_stline(L, sl);
}

/* Returns an array containing all headers of the HTTP message. it relies on
 * hlua_http_get_headers().
 */
__LJMP static int hlua_http_msg_get_headers(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 1, "get_headers"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	return hlua_http_get_headers(L, msg);
}

/* Deletes all occurrences of an header in the HTTP message matching on its
 * name. It relies on hlua_http_del_hdr().
 */
__LJMP static int hlua_http_msg_del_hdr(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 2, "del_header"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	return hlua_http_del_hdr(L, msg);
}

/* Matches the full value line of all occurrences of an header in the HTTP
 * message given its name against a regex and replaces it if it matches. It
 * relies on hlua_http_rep_hdr().
 */
__LJMP static int hlua_http_msg_rep_hdr(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 4, "rep_header"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	return hlua_http_rep_hdr(L, msg, 1);
}

/* Matches all comma-separated values of all occurrences of an header in the HTTP
 * message given its name against a regex and replaces it if it matches. It
 * relies on hlua_http_rep_hdr().
 */
__LJMP static int hlua_http_msg_rep_val(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 4, "rep_value"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	return hlua_http_rep_hdr(L, msg, 0);
}

/* Add an header in the HTTP message. It relies on hlua_http_add_hdr() */
__LJMP static int hlua_http_msg_add_hdr(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 3, "add_header"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	return hlua_http_add_hdr(L, msg);
}

/* Add an header in the HTTP message removing existing headers with the same
 * name. It relies on hlua_http_del_hdr() and hlua_http_add_hdr().
 */
__LJMP static int hlua_http_msg_set_hdr(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 3, "set_header"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	hlua_http_del_hdr(L, msg);
	return hlua_http_add_hdr(L, msg);
}

/* Rewrites the request method. It relies on http_req_replace_stline(). */
__LJMP static int hlua_http_msg_set_meth(lua_State *L)
{
	struct stream *s;
	struct http_msg *msg;
	const char *name;
	size_t name_len;

	MAY_LJMP(check_args(L, 2, "set_method"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if ((msg->chn->flags & CF_ISRESP) || msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	s = chn_strm(msg->chn);
	lua_pushboolean(L, http_req_replace_stline(0, name, name_len, s->be, s) != -1);
	return 1;
}

/* Rewrites the request path. It relies on http_req_replace_stline(). */
__LJMP static int hlua_http_msg_set_path(lua_State *L)
{
	struct stream *s;
	struct http_msg *msg;
	const char *name;
	size_t name_len;

	MAY_LJMP(check_args(L, 2, "set_path"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if ((msg->chn->flags & CF_ISRESP) || msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	s = chn_strm(msg->chn);
	lua_pushboolean(L, http_req_replace_stline(1, name, name_len, s->be, s) != -1);
	return 1;
}

/* Rewrites the request query-string. It relies on http_req_replace_stline(). */
__LJMP static int hlua_http_msg_set_query(lua_State *L)
{
	struct stream *s;
	struct http_msg *msg;
	const char *name;
	size_t name_len;

	MAY_LJMP(check_args(L, 2, "set_query"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if ((msg->chn->flags & CF_ISRESP) || msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	/* Check length. */
	if (name_len > trash.size - 1) {
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Add the mark question as prefix. */
	chunk_reset(&trash);
	trash.area[trash.data++] = '?';
	memcpy(trash.area + trash.data, name, name_len);
	trash.data += name_len;

	s = chn_strm(msg->chn);
	lua_pushboolean(L, http_req_replace_stline(2, trash.area, trash.data, s->be, s) != -1);
	return 1;
}

/* Rewrites the request URI. It relies on http_req_replace_stline(). */
__LJMP static int hlua_http_msg_set_uri(lua_State *L)
{
	struct stream *s;
	struct http_msg *msg;
	const char *name;
	size_t name_len;

	MAY_LJMP(check_args(L, 2, "set_uri"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	if ((msg->chn->flags & CF_ISRESP) || msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	s = chn_strm(msg->chn);
	lua_pushboolean(L, http_req_replace_stline(3, name, name_len, s->be, s) != -1);
	return 1;
}

/* Rewrites the response status code. It relies on http_res_set_status(). */
__LJMP static int hlua_http_msg_set_status(lua_State *L)
{
	struct http_msg *msg;
	unsigned int code;
	const char *reason;
	size_t reason_len;

	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	code = MAY_LJMP(luaL_checkinteger(L, 2));
	reason = MAY_LJMP(luaL_optlstring(L, 3, NULL, &reason_len));

	if (!(msg->chn->flags & CF_ISRESP) || msg->msg_state > HTTP_MSG_BODY)
		WILL_LJMP(lua_error(L));

	lua_pushboolean(L, http_res_set_status(code, ist2(reason, reason_len), chn_strm(msg->chn)) != -1);
	return 1;
}

/* Returns true if the HTTP message is full. */
__LJMP static int hlua_http_msg_is_full(lua_State *L)
{
	struct http_msg *msg;

	MAY_LJMP(check_args(L, 1, "is_full"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	lua_pushboolean(L, channel_full(msg->chn, 0));
	return 1;
}

/* Returns true if the HTTP message may still receive data. */
__LJMP static int hlua_http_msg_may_recv(lua_State *L)
{
	struct http_msg *msg;
	struct htx *htx;

	MAY_LJMP(check_args(L, 1, "may_recv"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	htx = htxbuf(&msg->chn->buf);
	lua_pushboolean(L, (htx_expect_more(htx) && !channel_input_closed(msg->chn) && channel_may_recv(msg->chn)));
	return 1;
}

/* Returns true if the HTTP message EOM was received */
__LJMP static int hlua_http_msg_is_eom(lua_State *L)
{
	struct http_msg *msg;
	struct htx *htx;

	MAY_LJMP(check_args(L, 1, "may_recv"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	htx = htxbuf(&msg->chn->buf);
	lua_pushboolean(L, !htx_expect_more(htx));
	return 1;
}

/* Returns the number of bytes available in the input side of the HTTP
 * message. This function never fails.
 */
__LJMP static int hlua_http_msg_get_in_len(lua_State *L)
{
	struct http_msg *msg;
	size_t output, input;

	MAY_LJMP(check_args(L, 1, "input"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	hlua_http_msg_filter(L, 1, msg, &output, &input);
	lua_pushinteger(L, input);
	return 1;
}

/* Returns the number of bytes available in the output side of the HTTP
 * message. This function never fails.
 */
__LJMP static int hlua_http_msg_get_out_len(lua_State *L)
{
	struct http_msg *msg;
	size_t output, input;

	MAY_LJMP(check_args(L, 1, "output"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	hlua_http_msg_filter(L, 1, msg, &output, &input);
	lua_pushinteger(L, output);
	return 1;
}

/* Copies at most <len> bytes of DATA blocks from the HTTP message <msg>
 * starting at the offset <offset> and put it in a string LUA variables. It
 * returns the built string length. It stops on the first non-DATA HTX
 * block. This function is called during the payload filtering, so the headers
 * are already scheduled for output (from the filter point of view).
 */
static int _hlua_http_msg_dup(struct http_msg *msg, lua_State *L, size_t offset, size_t len)
{
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_blk *blk;
	struct htx_ret htxret;
	luaL_Buffer b;
	int ret = 0;

	luaL_buffinit(L, &b);
	htxret = htx_find_offset(htx, offset);
	for (blk = htxret.blk, offset = htxret.ret; blk && len; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist v;

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v = istadv(v, offset);
				v = isttrim(v, len);

				luaL_addlstring(&b, v.ptr, v.len);
				ret += v.len;
				break;

			default:
				if (!ret)
					goto no_data;
				goto end;
		}
		offset = 0;
	}

end:
	if (!ret && (htx->flags & HTX_FL_EOM))
		goto no_data;
	luaL_pushresult(&b);
	return ret;

  no_data:
	/* Remove the empty string and push nil on the stack */
	lua_pop(L, 1);
	lua_pushnil(L);
	return 0;
}

/* Copies the string <str> to the HTTP message <msg> at the offset
 * <offset>. This function returns -1 if data cannot be copied. Otherwise, it
 * returns the amount of data written. This function is responsible to update
 * the filter context.
 */
static int _hlua_http_msg_insert(struct http_msg *msg, struct filter *filter, struct ist str, size_t offset)
{
	struct htx *htx = htx_from_buf(&msg->chn->buf);
	struct htx_ret htxret;
	int /*max, */ret = 0;

	/* Nothing to do, just return */
	if (unlikely(istlen(str) == 0))
		goto end;

	if (istlen(str) > htx_free_data_space(htx)) {
		ret = -1;
		goto end;
	}

	htxret = htx_find_offset(htx, offset);
	if (!htxret.blk || htx_get_blk_type(htxret.blk) != HTX_BLK_DATA) {
		if (!htx_add_last_data(htx, str))
			goto end;
	}
	else {
		struct ist v = htx_get_blk_value(htx, htxret.blk);
		v.ptr += htxret.ret;
		v.len  = 0;
		if (!htx_replace_blk_value(htx, htxret.blk, v, str))
			goto end;
	}
	ret = str.len;
	if (ret) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;
		flt_update_offsets(filter, msg->chn, ret);
		flt_ctx->cur_len[CHN_IDX(msg->chn)] += ret;
	}

  end:
	htx_to_buf(htx, &msg->chn->buf);
	return ret;
}

/* Helper function removing at most <len> bytes of DATA blocks at the absolute
 * position <offset>. It stops on the first non-DATA HTX block. This function is
 * called during the payload filtering, so the headers are already scheduled for
 * output (from the filter point of view). This function is responsible to
 * update the filter context.
 */
static void _hlua_http_msg_delete(struct http_msg *msg, struct filter *filter, size_t offset, size_t len)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;
	struct htx *htx = htx_from_buf(&msg->chn->buf);
	struct htx_blk *blk;
	struct htx_ret htxret;
	size_t ret = 0;

	/* Be sure <len> is always the amount of DATA to remove */
	if (htx->data == offset+len && htx_get_tail_type(htx) == HTX_BLK_DATA) {
		/* When htx tail type == HTX_BLK_DATA, no need to take care
		 * of special blocks like HTX_BLK_EOT.
		 * We simply truncate after offset
		 * (truncate targeted blk and discard the following ones)
		 */
		htx_truncate(htx, offset);
		ret = len;
		goto end;
	}

	htxret = htx_find_offset(htx, offset);
	blk = htxret.blk;
	if (htxret.ret) {
		/* dealing with offset: we need to trim targeted blk */
		struct ist v;

		if (htx_get_blk_type(blk) != HTX_BLK_DATA)
			goto end;

		v = htx_get_blk_value(htx, blk);
		v = istadv(v, htxret.ret);

		v = isttrim(v, len);
		/* trimming data in blk: discard everything after the offset
		 * (replace 'v' with 'IST_NULL')
		 */
		blk = htx_replace_blk_value(htx, blk, v, IST_NULL);
		if (blk && v.len < len) {
			/* In this case, caller wants to keep removing data,
			 * but we need to spare current blk
			 * because it was already trimmed
			 */
			blk = htx_get_next_blk(htx, blk);
		}
		len -= v.len;
		ret += v.len;
	}


	while (blk && len) {
		/* there is more data that needs to be discarded */
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);

		switch (type) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_DATA:
				if (len < sz) {
					/* don't discard whole blk, only part of it
					 * (from the beginning)
					 */
					htx_cut_data_blk(htx, blk, len);
					ret += len;
					goto end;
				}
				break;

			default:
				/* HTX_BLK_EOT blk won't be removed */
				goto end;
		}

		/* Remove all the data block */
		len -= sz;
		ret += sz;
		blk = htx_remove_blk(htx, blk);
	}

end:
	flt_update_offsets(filter, msg->chn, -ret);
	flt_ctx->cur_len[CHN_IDX(msg->chn)] -= ret;
	/* WARNING: we don't call htx_to_buf() on purpose, because we don't want
	 *          to loose the EOM flag if the message is empty.
	 */
}

/* Copies input data found in an HTTP message. Unlike the channel function used
 * to duplicate raw data, this one can only be called inside a filter, from
 * http_payload callback. So it cannot yield. An exception is returned if it is
 * called from another callback. If nothing was copied, a nil value is pushed on
 * the stack.
 */
__LJMP static int hlua_http_msg_get_body(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	size_t output, input;
	int offset, len;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'data' expects at most 2 arguments"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	filter = hlua_http_msg_filter(L, 1, msg, &output, &input);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	if (!ci_data(msg->chn) && channel_input_closed(msg->chn)) {
		lua_pushnil(L);
		return 1;
	}

	offset = output;
	if (lua_gettop(L) > 1) {
		offset = MAY_LJMP(luaL_checkinteger(L, 2));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}
	len = output + input - offset;
	if (lua_gettop(L) == 3) {
		len = MAY_LJMP(luaL_checkinteger(L, 3));
		if (!len)
			goto dup;
		if (len == -1)
			len = global.tune.bufsize;
		if (len < 0) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

  dup:
	_hlua_http_msg_dup(msg, L, offset, len);
	return 1;
}

/* Appends a string to the HTTP message, after all existing DATA blocks but
 * before the trailers, if any. It returns the amount of data written or -1 if
 * nothing was copied. Unlike the channel function used to append data, this one
 * can only be called inside a filter, from http_payload callback. So it cannot
 * yield. An exception is returned if it is called from another callback.
 */
__LJMP static int hlua_http_msg_append(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	const char *str;
	size_t offset, len, sz;
	int ret;

	MAY_LJMP(check_args(L, 2, "append"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	filter = hlua_http_msg_filter(L, 1, msg, &offset, &len);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	ret = _hlua_http_msg_insert(msg, filter, ist2(str, sz), offset+len);
	lua_pushinteger(L, ret);
	return 1;
}

/* Prepends a string to the HTTP message, before all existing DATA blocks. It
 * returns the amount of data written or -1 if nothing was copied. Unlike the
 * channel function used to prepend data, this one can only be called inside a
 * filter, from http_payload callback. So it cannot yield. An exception is
 * returned if it is called from another callback.
 */
__LJMP static int hlua_http_msg_prepend(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	const char *str;
	size_t offset, len, sz;
	int ret;

	MAY_LJMP(check_args(L, 2, "prepend"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	filter = hlua_http_msg_filter(L, 1, msg, &offset, &len);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	ret = _hlua_http_msg_insert(msg, filter, ist2(str, sz), offset);
	lua_pushinteger(L, ret);
	return 1;
}

/* Inserts a string to the HTTP message at a given offset. By default the string
 * is appended at the end of DATA blocks. It returns the amount of data written
 * or -1 if nothing was copied. Unlike the channel function used to insert data,
 * this one can only be called inside a filter, from http_payload callback. So
 * it cannot yield. An exception is returned if it is called from another
 * callback.
 */
__LJMP static int hlua_http_msg_insert_data(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	const char *str;
	size_t input, output, sz;
	int offset;
	int ret;

	if (lua_gettop(L) < 2 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'insert' expects at least 1 argument and at most 2 arguments"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	filter = hlua_http_msg_filter(L, 1, msg, &output, &input);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 2) {
		offset = MAY_LJMP(luaL_checkinteger(L, 3));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset > output + input) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	ret = _hlua_http_msg_insert(msg, filter, ist2(str, sz), offset);
	lua_pushinteger(L, ret);
	return 1;
}

/* Removes a given amount of data from the HTTP message at a given offset. By
 * default all DATA blocks are removed. It returns the amount of data
 * removed. Unlike the channel function used to remove data, this one can only
 * be called inside a filter, from http_payload callback. So it cannot yield. An
 * exception is returned if it is called from another callback.
 */
__LJMP static int hlua_http_msg_del_data(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	size_t input, output;
	int offset, len;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "'remove' expects at most 2 arguments"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	filter = hlua_http_msg_filter(L, 1, msg, &output, &input);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 1) {
		offset = MAY_LJMP(luaL_checkinteger(L, 2));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset > output + input) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	len = output + input - offset;
	if (lua_gettop(L) == 3) {
		len = MAY_LJMP(luaL_checkinteger(L, 3));
		if (!len)
			goto end;
		if (len == -1)
			len = output + input - offset;
		if (len < 0 || offset + len > output + input) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	_hlua_http_msg_delete(msg, filter, offset, len);

  end:
	lua_pushinteger(L, len);
	return 1;
}

/* Replaces a given amount of data at the given offset by a string. By default,
 * all remaining data are removed, accordingly to the filter context. It returns
 * the amount of data written or -1 if nothing was copied. Unlike the channel
 * function used to replace data, this one can only be called inside a filter,
 * from http_payload callback. So it cannot yield. An exception is returned if
 * it is called from another callback.
 */
__LJMP static int hlua_http_msg_set_data(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	struct htx *htx;
	const char *str;
	size_t input, output, sz;
	int offset, len;
	int ret;

	if (lua_gettop(L) < 2 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set' expects at least 1 argument and at most 3 arguments"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	filter = hlua_http_msg_filter(L, 1, msg, &output, &input);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	offset = output;
	if (lua_gettop(L) > 2) {
		offset = MAY_LJMP(luaL_checkinteger(L, 3));
		if (offset < 0)
			offset = MAX(0, (int)input + offset);
		offset += output;
		if (offset < output || offset > input + output) {
			lua_pushfstring(L, "offset out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

	len = output + input - offset;
	if (lua_gettop(L) == 4) {
		len = MAY_LJMP(luaL_checkinteger(L, 4));
		if (!len)
			goto set;
		if (len == -1)
			len = output + input - offset;
		if (len < 0 || offset + len > output + input) {
			lua_pushfstring(L, "length out of range.");
			WILL_LJMP(lua_error(L));
		}
	}

  set:
	/* Be sure we can copied the string once input data will be removed. */
	htx = htx_from_buf(&msg->chn->buf);
	if (sz > htx_free_data_space(htx) + len)
		lua_pushinteger(L, -1);
	else {
		_hlua_http_msg_delete(msg, filter, offset, len);
		ret = _hlua_http_msg_insert(msg, filter, ist2(str, sz), offset);
		lua_pushinteger(L, ret);
	}
	return 1;
}

/* Prepends data into an HTTP message and forward it, from the filter point of
 * view. It returns the amount of data written or -1 if nothing was sent. Unlike
 * the channel function used to send data, this one can only be called inside a
 * filter, from http_payload callback. So it cannot yield. An exception is
 * returned if it is called from another callback.
 */
__LJMP static int hlua_http_msg_send(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	struct htx *htx;
	const char *str;
	size_t offset, len, sz;
	int ret;

	MAY_LJMP(check_args(L, 2, "send"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	str = MAY_LJMP(luaL_checklstring(L, 2, &sz));
	filter = hlua_http_msg_filter(L, 1, msg, &offset, &len);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	/* Return an error if the channel's output is closed */
	if (unlikely(channel_output_closed(msg->chn))) {
		lua_pushinteger(L, -1);
		return 1;
	}

	htx = htx_from_buf(&msg->chn->buf);
	if (sz > htx_free_data_space(htx)) {
		lua_pushinteger(L, -1);
		return 1;
	}

	ret = _hlua_http_msg_insert(msg, filter, ist2(str, sz), offset);
	if (ret > 0) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		FLT_OFF(filter, msg->chn) += ret;
		flt_ctx->cur_len[CHN_IDX(msg->chn)] -= ret;
		flt_ctx->cur_off[CHN_IDX(msg->chn)] += ret;
	}

	lua_pushinteger(L, ret);
	return 1;
}

/* Forwards a given amount of bytes. It return -1 if the channel's output is
 * closed. Otherwise, it returns the number of bytes forwarded. Unlike the
 * channel function used to forward data, this one can only be called inside a
 * filter, from http_payload callback. So it cannot yield. An exception is
 * returned if it is called from another callback. All other functions deal with
 * DATA block, this one not.
*/
__LJMP static int hlua_http_msg_forward(lua_State *L)
{
	struct http_msg *msg;
	struct filter *filter;
	size_t offset, len;
	int fwd, ret = 0;

	MAY_LJMP(check_args(L, 2, "forward"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));

	if (msg->msg_state < HTTP_MSG_DATA)
		WILL_LJMP(lua_error(L));

	fwd = MAY_LJMP(luaL_checkinteger(L, 2));
	filter = hlua_http_msg_filter(L, 1, msg, &offset, &len);
	if (!filter || !hlua_filter_from_payload(filter))
		WILL_LJMP(lua_error(L));

	/* Nothing to do, just return */
	if (!fwd)
		goto end;

	/* Return an error if the channel's output is closed */
	if (unlikely(channel_output_closed(msg->chn))) {
		ret = -1;
		goto end;
	}

	ret = fwd;
	if (ret > len)
		ret = len;

	if (ret) {
		struct hlua_flt_ctx *flt_ctx = filter->ctx;

		FLT_OFF(filter, msg->chn) += ret;
		flt_ctx->cur_off[CHN_IDX(msg->chn)] += ret;
		flt_ctx->cur_len[CHN_IDX(msg->chn)] -= ret;
	}

  end:
	lua_pushinteger(L, ret);
	return 1;
}

/* Set EOM flag on the HTX message.
 *
 * NOTE: Not sure it is a good idea to manipulate this flag but for now I don't
 *       really know how to do without this feature.
 */
__LJMP static int hlua_http_msg_set_eom(lua_State *L)
{
	struct http_msg *msg;
	struct htx *htx;

	MAY_LJMP(check_args(L, 1, "set_eom"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	htx = htxbuf(&msg->chn->buf);
	htx->flags |= HTX_FL_EOM;
	return 0;
}

/* Unset EOM flag on the HTX message.
 *
 * NOTE: Not sure it is a good idea to manipulate this flag but for now I don't
 *       really know how to do without this feature.
 */
__LJMP static int hlua_http_msg_unset_eom(lua_State *L)
{
	struct http_msg *msg;
	struct htx *htx;

	MAY_LJMP(check_args(L, 1, "set_eom"));
	msg = MAY_LJMP(hlua_checkhttpmsg(L, 1));
	htx = htxbuf(&msg->chn->buf);
	htx->flags &= ~HTX_FL_EOM;
	return 0;
}

/*
 *
 *
 * Class HTTPClient
 *
 *
 */
__LJMP static struct hlua_httpclient *hlua_checkhttpclient(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_httpclient_ref));
}


/* stops the httpclient and ask it to kill itself */
__LJMP static int hlua_httpclient_gc(lua_State *L)
{
	struct hlua_httpclient *hlua_hc;

	MAY_LJMP(check_args(L, 1, "__gc"));

	hlua_hc = MAY_LJMP(hlua_checkhttpclient(L, 1));

	if (MT_LIST_DELETE(&hlua_hc->by_hlua)) {
		/* we won the race against hlua_httpclient_destroy_all() */
		httpclient_stop_and_destroy(hlua_hc->hc);
		hlua_hc->hc = NULL;
	}

	return 0;
}


__LJMP static int hlua_httpclient_new(lua_State *L)
{
	struct hlua_httpclient *hlua_hc;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	/* Check stack size. */
	if (!lua_checkstack(L, 3)) {
		hlua_pusherror(L, "httpclient: full stack");
		goto err;
	}
	/* Create the object: obj[0] = userdata. */
	lua_newtable(L);
	hlua_hc = MAY_LJMP(lua_newuserdata(L, sizeof(*hlua_hc)));
	lua_rawseti(L, -2, 0);
	memset(hlua_hc, 0, sizeof(*hlua_hc));

	hlua_hc->hc = httpclient_new(hlua, 0, IST_NULL);
	if (!hlua_hc->hc)
		goto err;

	MT_LIST_APPEND(&hlua->hc_list, &hlua_hc->by_hlua);

	/* Pop a class stream metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_httpclient_ref);
	lua_setmetatable(L, -2);

	return 1;

 err:
	WILL_LJMP(lua_error(L));
	return 0;
}


/*
 * Callback of the httpclient, this callback wakes the lua task up, once the
 * httpclient receives some data
 *
 */

static void hlua_httpclient_cb(struct httpclient *hc)
{
	struct hlua *hlua = hc->caller;

	if (!hlua || !hlua->task)
		return;

	task_wakeup(hlua->task, TASK_WOKEN_MSG);
}

/*
 * Fill the lua stack with headers from the httpclient response
 * This works the same way as the hlua_http_get_headers() function
 */
__LJMP static int hlua_httpclient_get_headers(lua_State *L, struct hlua_httpclient *hlua_hc)
{
	struct http_hdr *hdr;

	lua_newtable(L);

	for (hdr = hlua_hc->hc->res.hdrs; hdr && isttest(hdr->n); hdr++) {
		struct ist n, v;
		int len;

		n = hdr->n;
		v = hdr->v;

		/* Check for existing entry:
		 * assume that the table is on the top of the stack, and
		 * push the key in the stack, the function lua_gettable()
		 * perform the lookup.
		 */

		lua_pushlstring(L, n.ptr, n.len);
		lua_gettable(L, -2);

		switch (lua_type(L, -1)) {
			case LUA_TNIL:
				/* Table not found, create it. */
				lua_pop(L, 1); /* remove the nil value. */
				lua_pushlstring(L, n.ptr, n.len);  /* push the header name as key. */
				lua_newtable(L); /* create and push empty table. */
				lua_pushlstring(L, v.ptr, v.len); /* push header value. */
				lua_rawseti(L, -2, 0); /* index header value (pop it). */
				lua_rawset(L, -3); /* index new table with header name (pop the values). */
				break;

			case LUA_TTABLE:
				/* Entry found: push the value in the table. */
				len = lua_rawlen(L, -1);
				lua_pushlstring(L, v.ptr, v.len); /* push header value. */
				lua_rawseti(L, -2, len+1); /* index header value (pop it). */
				lua_pop(L, 1); /* remove the table (it is stored in the main table). */
				break;

			default:
				/* Other cases are errors. */
				hlua_pusherror(L, "internal error during the parsing of headers.");
				WILL_LJMP(lua_error(L));
		}
	}
	return 1;
}

/*
 * Allocate and return an array of http_hdr ist extracted from the <headers> lua table
 *
 * Caller must free the result
 */
struct http_hdr *hlua_httpclient_table_to_hdrs(lua_State *L)
{
	struct http_hdr hdrs[global.tune.max_http_hdr];
	struct http_hdr *result = NULL;
	uint32_t hdr_num = 0;

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		struct ist name, value;
		const char *n, *v;
		size_t nlen, vlen;

		if (!lua_isstring(L, -2) || !lua_istable(L, -1)) {
			/* Skip element if the key is not a string or if the value is not a table */
			goto next_hdr;
		}

		n = lua_tolstring(L, -2, &nlen);
		name = ist2(n, nlen);

		/* Loop on header's values */
		lua_pushnil(L);
		while (lua_next(L, -2)) {
			if (!lua_isstring(L, -1)) {
				/* Skip the value if it is not a string */
				goto next_value;
			}

			v = lua_tolstring(L, -1, &vlen);
			value = ist2(v, vlen);
			name = ist2(n, nlen);

			hdrs[hdr_num].n = istdup(name);
			hdrs[hdr_num].v = istdup(value);

			hdr_num++;

		  next_value:
			lua_pop(L, 1);
		}

	  next_hdr:
		lua_pop(L, 1);

	}

	if (hdr_num) {
		/* alloc and copy the headers in the httpclient struct */
		result = calloc((hdr_num + 1), sizeof(*result));
		if (!result)
			goto skip_headers;
		memcpy(result, hdrs, sizeof(struct http_hdr) * (hdr_num + 1));

		result[hdr_num].n = IST_NULL;
		result[hdr_num].v = IST_NULL;
	}

skip_headers:

	return result;
}


/*
 * For each yield, checks if there is some data in the httpclient and push them
 * in the lua buffer, once the httpclient finished its job, push the result on
 * the stack
 */
__LJMP static int hlua_httpclient_rcv_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct buffer *tr;
	int res;
	struct hlua *hlua = hlua_gethlua(L);
	struct hlua_httpclient *hlua_hc = hlua_checkhttpclient(L, 1);


	tr = get_trash_chunk();

	res = httpclient_res_xfer(hlua_hc->hc, tr);
	luaL_addlstring(&hlua_hc->b, b_orig(tr), res);

	if (!httpclient_data(hlua_hc->hc) && httpclient_ended(hlua_hc->hc)) {

		luaL_pushresult(&hlua_hc->b);
		lua_settable(L, -3);

		lua_pushstring(L, "status");
		lua_pushinteger(L, hlua_hc->hc->res.status);
		lua_settable(L, -3);


		lua_pushstring(L, "reason");
		lua_pushlstring(L, hlua_hc->hc->res.reason.ptr, hlua_hc->hc->res.reason.len);
		lua_settable(L, -3);

		lua_pushstring(L, "headers");
		hlua_httpclient_get_headers(L, hlua_hc);
		lua_settable(L, -3);

		return 1;
	}

	if (httpclient_data(hlua_hc->hc))
		task_wakeup(hlua->task, TASK_WOKEN_MSG);

	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_httpclient_rcv_yield, TICK_ETERNITY, 0));

	return 0;
}

/*
 * Call this when trying to stream a body during a request
 */
__LJMP static int hlua_httpclient_snd_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua *hlua;
	struct hlua_httpclient *hlua_hc = hlua_checkhttpclient(L, 1);
	const char *body_str = NULL;
	int ret;
	int end = 0;
	size_t buf_len;
	size_t to_send = 0;

	hlua = hlua_gethlua(L);

	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'get' function is only allowed in "
		                     "'frontend', 'backend' or 'task'"));

	ret = lua_getfield(L, -1, "body");
	if (ret != LUA_TSTRING)
		goto rcv;

	body_str = lua_tolstring(L, -1, &buf_len);
	lua_pop(L, 1);

	to_send = buf_len - hlua_hc->sent;

	if ((hlua_hc->sent + to_send) >= buf_len)
		end = 1;

	/* the end flag is always set since we are using the whole remaining size */
	hlua_hc->sent += httpclient_req_xfer(hlua_hc->hc, ist2(body_str + hlua_hc->sent, to_send), end);

	if (buf_len > hlua_hc->sent) {
		/* still need to process the buffer */
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_httpclient_snd_yield, TICK_ETERNITY, 0));
	} else {
		goto rcv;
		/* we sent the whole request buffer we can recv */
	}
	return 0;

rcv:

	/* we return a "res" object */
	lua_newtable(L);

	lua_pushstring(L, "body");
	luaL_buffinit(L, &hlua_hc->b);

	task_wakeup(hlua->task, TASK_WOKEN_MSG);
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_httpclient_rcv_yield, TICK_ETERNITY, 0));

	return 1;
}

/*
 * Send an HTTP request and wait for a response
 */

__LJMP static int hlua_httpclient_send(lua_State *L, enum http_meth_t meth)
{
	struct hlua_httpclient *hlua_hc;
	struct http_hdr *hdrs = NULL;
	struct http_hdr *hdrs_i = NULL;
	struct hlua *hlua;
	const char *url_str = NULL;
	const char *body_str = NULL;
	size_t buf_len = 0;
	int ret;

	hlua = hlua_gethlua(L);

	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'get' function is only allowed in "
		                     "'frontend', 'backend' or 'task'"));

	if (lua_gettop(L) != 2 || lua_type(L, -1) != LUA_TTABLE)
		WILL_LJMP(luaL_error(L, "'get' needs a table as argument"));

	hlua_hc = hlua_checkhttpclient(L, 1);

	lua_pushnil(L);  /* first key */
	while (lua_next(L, 2)) {
		if (strcmp(lua_tostring(L, -2), "dst") == 0) {
			if (httpclient_set_dst(hlua_hc->hc, lua_tostring(L, -1)) < 0)
				WILL_LJMP(luaL_error(L, "Can't use the 'dst' argument"));

		} else if (strcmp(lua_tostring(L, -2), "url") == 0) {
			if (lua_type(L, -1) != LUA_TSTRING)
				WILL_LJMP(luaL_error(L, "invalid parameter in 'url', must be a string"));
			url_str = lua_tostring(L, -1);

		} else if (strcmp(lua_tostring(L, -2), "timeout") == 0) {
			if (lua_type(L, -1) != LUA_TNUMBER)
				WILL_LJMP(luaL_error(L, "invalid parameter in 'timeout', must be a number"));
			httpclient_set_timeout(hlua_hc->hc, lua_tointeger(L, -1));

		} else if (strcmp(lua_tostring(L, -2), "headers") == 0) {
			if (lua_type(L, -1) != LUA_TTABLE)
				WILL_LJMP(luaL_error(L, "invalid parameter in 'headers', must be a table"));
			hdrs = hlua_httpclient_table_to_hdrs(L);

		} else if (strcmp(lua_tostring(L, -2), "body") == 0) {
			if (lua_type(L, -1) != LUA_TSTRING)
				WILL_LJMP(luaL_error(L, "invalid parameter in 'body', must be a string"));
			body_str = lua_tolstring(L, -1, &buf_len);

		} else {
			WILL_LJMP(luaL_error(L, "'%s' invalid parameter name", lua_tostring(L, -2)));
		}
		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	if (!url_str) {
		WILL_LJMP(luaL_error(L, "'get' need a 'url' argument"));
		return 0;
	}

	hlua_hc->sent = 0;

	istfree(&hlua_hc->hc->req.url);
	hlua_hc->hc->req.url = istdup(ist(url_str));
	hlua_hc->hc->req.meth = meth;

	/* update the httpclient callbacks */
	hlua_hc->hc->ops.res_stline = hlua_httpclient_cb;
	hlua_hc->hc->ops.res_headers = hlua_httpclient_cb;
	hlua_hc->hc->ops.res_payload = hlua_httpclient_cb;
	hlua_hc->hc->ops.res_end = hlua_httpclient_cb;

	/* a body is available, it will use the request callback */
	if (body_str && buf_len) {
		hlua_hc->hc->ops.req_payload = hlua_httpclient_cb;
	}

	ret = httpclient_req_gen(hlua_hc->hc, hlua_hc->hc->req.url, meth, hdrs, IST_NULL);

	/* free the temporary headers array */
	hdrs_i = hdrs;
	while (hdrs_i && isttest(hdrs_i->n)) {
		istfree(&hdrs_i->n);
		istfree(&hdrs_i->v);
		hdrs_i++;
	}
	ha_free(&hdrs);


	if (ret != ERR_NONE) {
		WILL_LJMP(luaL_error(L, "Can't generate the HTTP request"));
		return 0;
	}

	if (!httpclient_start(hlua_hc->hc))
		WILL_LJMP(luaL_error(L, "couldn't start the httpclient"));

	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_httpclient_snd_yield, TICK_ETERNITY, 0));

	return 0;
}

/*
 * Sends an HTTP HEAD request and wait for a response
 *
 * httpclient:head(url, headers, payload)
 */
__LJMP static int hlua_httpclient_head(lua_State *L)
{
	return hlua_httpclient_send(L, HTTP_METH_HEAD);
}

/*
 * Send an HTTP GET request and wait for a response
 *
 * httpclient:get(url, headers, payload)
 */
__LJMP static int hlua_httpclient_get(lua_State *L)
{
	return hlua_httpclient_send(L, HTTP_METH_GET);

}

/*
 * Sends an HTTP PUT request and wait for a response
 *
 * httpclient:put(url, headers, payload)
 */
__LJMP static int hlua_httpclient_put(lua_State *L)
{
	return hlua_httpclient_send(L, HTTP_METH_PUT);
}

/*
 * Send an HTTP POST request and wait for a response
 *
 * httpclient:post(url, headers, payload)
 */
__LJMP static int hlua_httpclient_post(lua_State *L)
{
	return hlua_httpclient_send(L, HTTP_METH_POST);
}


/*
 * Sends an HTTP DELETE request and wait for a response
 *
 * httpclient:delete(url, headers, payload)
 */
__LJMP static int hlua_httpclient_delete(lua_State *L)
{
	return hlua_httpclient_send(L, HTTP_METH_DELETE);
}

/*
 *
 *
 * Class TXN
 *
 *
 */

/* Returns a struct hlua_session if the stack entry "ud" is
 * a class stream, otherwise it throws an error.
 */
__LJMP static struct hlua_txn *hlua_checktxn(lua_State *L, int ud)
{
	return MAY_LJMP(hlua_checkudata(L, ud, class_txn_ref));
}

__LJMP static int hlua_set_var(lua_State *L)
{
	struct hlua_txn *htxn;
	const char *name;
	size_t len;
	struct sample smp;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set_var' needs between 3 and 4 arguments"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));

	/* Converts the third argument in a sample. */
	memset(&smp, 0, sizeof(smp));
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. We don't need to dup the smp, vars API
	 * already takes care of duplicating dynamic var data.
	 */
	smp_set_owner(&smp, htxn->p, htxn->s->sess, htxn->s, htxn->dir & SMP_OPT_DIR);

	if (lua_gettop(L) == 4 && lua_toboolean(L, 4))
		lua_pushboolean(L, vars_set_by_name_ifexist(name, len, &smp) != 0);
	else
		lua_pushboolean(L, vars_set_by_name(name, len, &smp) != 0);

	return 1;
}

__LJMP static int hlua_unset_var(lua_State *L)
{
	struct hlua_txn *htxn;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "unset_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));

	/* Unset the variable. */
	smp_set_owner(&smp, htxn->p, htxn->s->sess, htxn->s, htxn->dir & SMP_OPT_DIR);
	lua_pushboolean(L, vars_unset_by_name_ifexist(name, len, &smp) != 0);
	return 1;
}

__LJMP static int hlua_get_var(lua_State *L)
{
	struct hlua_txn *htxn;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "get_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));

	smp_set_owner(&smp, htxn->p, htxn->s->sess, htxn->s, htxn->dir & SMP_OPT_DIR);
	if (!vars_get_by_name(name, len, &smp, NULL)) {
		lua_pushnil(L);
		return 1;
	}

	return MAY_LJMP(hlua_smp2lua(L, &smp));
}

__LJMP static int hlua_set_priv(lua_State *L)
{
	struct hlua *hlua;

	MAY_LJMP(check_args(L, 2, "set_priv"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	/* Remove previous value. */
	luaL_unref(L, LUA_REGISTRYINDEX, hlua->Mref);

	/* Get and store new value. */
	lua_pushvalue(L, 2); /* Copy the element 2 at the top of the stack. */
	hlua->Mref = luaL_ref(L, LUA_REGISTRYINDEX); /* pop the previously pushed value. */

	return 0;
}

__LJMP static int hlua_get_priv(lua_State *L)
{
	struct hlua *hlua;

	MAY_LJMP(check_args(L, 1, "get_priv"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* Create stack entry containing a class TXN. This function
 * return 0 if the stack does not contains free slots,
 * otherwise it returns 1.
 */
__LJMP static int hlua_txn_new(lua_State *L, struct stream *s, struct proxy *p, int dir, int flags)
{
	struct hlua_txn *htxn;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* NOTE: The allocation never fails. The failure
	 * throw an error, and the function never returns.
	 * if the throw is not available, the process is aborted.
	 */
	/* Create the object: obj[0] = userdata. */
	lua_newtable(L);
	htxn = lua_newuserdata(L, sizeof(*htxn));
	lua_rawseti(L, -2, 0);

	htxn->s = s;
	htxn->p = p;
	htxn->dir = dir;
	htxn->flags = flags;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, htxn, HLUA_F_MAY_USE_HTTP))
		return 0;
	lua_rawset(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, htxn, HLUA_F_MAY_USE_HTTP | HLUA_F_AS_STRING))
		return 0;
	lua_rawset(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, htxn, 0))
		return 0;
	lua_rawset(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, htxn, HLUA_F_AS_STRING))
		return 0;
	lua_rawset(L, -3);

	/* Create the "req" field that contains the request channel object. */
	lua_pushstring(L, "req");
	if (!hlua_channel_new(L, &s->req))
		return 0;
	lua_rawset(L, -3);

	/* Create the "res" field that contains the response channel object. */
	lua_pushstring(L, "res");
	if (!hlua_channel_new(L, &s->res))
		return 0;
	lua_rawset(L, -3);

	/* Creates the HTTP object is the current proxy allows http. */
	lua_pushstring(L, "http");
	if (IS_HTX_STRM(s)) {
		if (!hlua_http_new(L, htxn))
			return 0;
	}
	else
		lua_pushnil(L);
	lua_rawset(L, -3);

	if ((htxn->flags & HLUA_TXN_CTX_MASK) == HLUA_TXN_FLT_CTX) {
		/* HTTPMessage object are created when a lua TXN is created from
		 * a filter context only
		 */

		/* Creates the HTTP-Request object is the current proxy allows http. */
		lua_pushstring(L, "http_req");
		if (p->mode == PR_MODE_HTTP) {
			if (!hlua_http_msg_new(L, &s->txn->req))
				return 0;
		}
		else
			lua_pushnil(L);
		lua_rawset(L, -3);

		/* Creates the HTTP-Response object is the current proxy allows http. */
		lua_pushstring(L, "http_res");
		if (p->mode == PR_MODE_HTTP) {
			if (!hlua_http_msg_new(L, &s->txn->rsp))
				return 0;
		}
		else
			lua_pushnil(L);
		lua_rawset(L, -3);
	}

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_txn_ref);
	lua_setmetatable(L, -2);

	return 1;
}

__LJMP static int hlua_txn_deflog(lua_State *L)
{
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "deflog"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));

	hlua_sendlog(htxn->s->be, htxn->s->logs.level, msg);
	return 0;
}

__LJMP static int hlua_txn_log(lua_State *L)
{
	int level;
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "log"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	level = MAY_LJMP(luaL_checkinteger(L, 2));
	msg = MAY_LJMP(luaL_checkstring(L, 3));

	if (level < 0 || level >= NB_LOG_LEVELS)
		WILL_LJMP(luaL_argerror(L, 1, "Invalid loglevel."));

	hlua_sendlog(htxn->s->be, level, msg);
	return 0;
}

__LJMP static int hlua_txn_log_debug(lua_State *L)
{
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "Debug"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));
	hlua_sendlog(htxn->s->be, LOG_DEBUG, msg);
	return 0;
}

__LJMP static int hlua_txn_log_info(lua_State *L)
{
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "Info"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));
	hlua_sendlog(htxn->s->be, LOG_INFO, msg);
	return 0;
}

__LJMP static int hlua_txn_log_warning(lua_State *L)
{
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "Warning"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));
	hlua_sendlog(htxn->s->be, LOG_WARNING, msg);
	return 0;
}

__LJMP static int hlua_txn_log_alert(lua_State *L)
{
	const char *msg;
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "Alert"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));
	hlua_sendlog(htxn->s->be, LOG_ALERT, msg);
	return 0;
}

__LJMP static int hlua_txn_set_fc_mark(lua_State *L)
{
	struct hlua_txn *htxn;
	int mark;

	MAY_LJMP(check_args(L, 2, "set_fc_mark"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	mark = MAY_LJMP(luaL_checkinteger(L, 2));

	conn_set_mark(objt_conn(htxn->s->sess->origin), mark);
	return 0;
}

__LJMP static int hlua_txn_set_fc_tos(lua_State *L)
{
	struct hlua_txn *htxn;
	int tos;

	MAY_LJMP(check_args(L, 2, "set_fc_tos"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	tos = MAY_LJMP(luaL_checkinteger(L, 2));

	conn_set_tos(objt_conn(htxn->s->sess->origin), tos);
	return 0;
}

__LJMP static int hlua_txn_set_loglevel(lua_State *L)
{
	struct hlua_txn *htxn;
	int ll;

	MAY_LJMP(check_args(L, 2, "set_loglevel"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	ll = MAY_LJMP(luaL_checkinteger(L, 2));

	if (ll < -1 || ll > NB_LOG_LEVELS)
		WILL_LJMP(luaL_argerror(L, 2, "Bad log level. It must be one of the following value:"
					" core.silent(-1), core.emerg(0), core.alert(1), core.crit(2), core.error(3),"
					" core.warning(4), core.notice(5), core.info(6) or core.debug(7)"));

	htxn->s->logs.level = (ll == -1) ? ll : ll + 1;
	return 0;
}

__LJMP static int hlua_txn_set_priority_class(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "set_priority_class"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	htxn->s->priority_class = queue_limit_class(MAY_LJMP(luaL_checkinteger(L, 2)));
	return 0;
}

__LJMP static int hlua_txn_set_priority_offset(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "set_priority_offset"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	htxn->s->priority_offset = queue_limit_offset(MAY_LJMP(luaL_checkinteger(L, 2)));
	return 0;
}

/* Forward the Reply object to the client. This function converts the reply in
 * HTX an push it to into the response channel. It is response to forward the
 * message and terminate the transaction. It returns 1 on success and 0 on
 * error. The Reply must be on top of the stack.
 */
__LJMP static int hlua_txn_forward_reply(lua_State *L, struct stream *s)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct h1m h1m;
	const char *status, *reason, *body;
	size_t status_len, reason_len, body_len;
	int ret, code, flags;

	code = 200;
	status = "200";
	status_len = 3;
	ret = lua_getfield(L, -1, "status");
	if (ret == LUA_TNUMBER) {
		code = lua_tointeger(L, -1);
		status = lua_tolstring(L, -1, &status_len);
	}
	lua_pop(L, 1);

	reason = http_get_reason(code);
	reason_len = strlen(reason);
	ret = lua_getfield(L, -1, "reason");
	if (ret == LUA_TSTRING)
		reason = lua_tolstring(L, -1, &reason_len);
	lua_pop(L, 1);

	body = NULL;
	body_len = 0;
	ret = lua_getfield(L, -1, "body");
	if (ret == LUA_TSTRING)
		body = lua_tolstring(L, -1, &body_len);
	lua_pop(L, 1);

	/* Prepare the response before inserting the headers */
	h1m_init_res(&h1m);
	htx = htx_from_buf(&s->res.buf);
	channel_htx_truncate(&s->res, htx);
	if (s->txn->req.flags & HTTP_MSGF_VER_11) {
		flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
				    ist2(status, status_len), ist2(reason, reason_len));
	}
	else {
		flags = HTX_SL_F_IS_RESP;
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.0"),
				    ist2(status, status_len), ist2(reason, reason_len));
	}
	if (!sl)
		goto fail;
	sl->info.res.status = code;

	/* Push in the stack the "headers" entry. */
	ret = lua_getfield(L, -1, "headers");
	if (ret != LUA_TTABLE)
		goto skip_headers;

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		struct ist name, value;
		const char *n, *v;
		size_t nlen, vlen;

		if (!lua_isstring(L, -2) || !lua_istable(L, -1)) {
			/* Skip element if the key is not a string or if the value is not a table */
			goto next_hdr;
		}

		n = lua_tolstring(L, -2, &nlen);
		name = ist2(n, nlen);
		if (isteqi(name, ist("content-length"))) {
			/* Always skip content-length header. It will be added
			 * later with the correct len
			 */
			goto next_hdr;
		}

		/* Loop on header's values */
		lua_pushnil(L);
		while (lua_next(L, -2)) {
			if (!lua_isstring(L, -1)) {
				/* Skip the value if it is not a string */
				goto next_value;
			}

			v = lua_tolstring(L, -1, &vlen);
			value = ist2(v, vlen);

			if (isteqi(name, ist("transfer-encoding")))
				h1_parse_xfer_enc_header(&h1m, value);
			if (!htx_add_header(htx, ist2(n, nlen), ist2(v, vlen)))
				goto fail;

		  next_value:
			lua_pop(L, 1);
		}

	  next_hdr:
		lua_pop(L, 1);
	}
  skip_headers:
	lua_pop(L, 1);

	/* Update h1m flags: CLEN is set if CHNK is not present */
	if (!(h1m.flags & H1_MF_CHNK)) {
		const char *clen = ultoa(body_len);

		h1m.flags |= H1_MF_CLEN;
		if (!htx_add_header(htx, ist("content-length"), ist(clen)))
			goto fail;
	}
	if (h1m.flags & (H1_MF_CLEN|H1_MF_CHNK))
		h1m.flags |= H1_MF_XFER_LEN;

	/* Update HTX start-line flags */
	if (h1m.flags & H1_MF_XFER_ENC)
		flags |= HTX_SL_F_XFER_ENC;
	if (h1m.flags & H1_MF_XFER_LEN) {
		flags |= HTX_SL_F_XFER_LEN;
		if (h1m.flags & H1_MF_CHNK)
			flags |= HTX_SL_F_CHNK;
		else if (h1m.flags & H1_MF_CLEN)
			flags |= HTX_SL_F_CLEN;
		if (h1m.body_len == 0)
			flags |= HTX_SL_F_BODYLESS;
	}
	sl->flags |= flags;


	if (!htx_add_endof(htx, HTX_BLK_EOH) ||
	    (body_len && !htx_add_data_atonce(htx, ist2(body, body_len))))
		goto fail;

	htx->flags |= HTX_FL_EOM;

	/* Now, forward the response and terminate the transaction */
	s->txn->status = code;
	htx_to_buf(htx, &s->res.buf);
	if (!http_forward_proxy_resp(s, 1))
		goto fail;

	return 1;

  fail:
	channel_htx_truncate(&s->res, htx);
	return 0;
}

/* Terminate a transaction if called from a lua action. For TCP streams,
 * processing is just aborted. Nothing is returned to the client and all
 * arguments are ignored. For HTTP streams, if a reply is passed as argument, it
 * is forwarded to the client before terminating the transaction. On success,
 * the function exits with ACT_RET_DONE code. If an error occurred, it exits
 * with ACT_RET_ERR code. If this function is not called from a lua action, it
 * just exits without any processing.
 */
__LJMP static int hlua_txn_done(lua_State *L)
{
	struct hlua_txn *htxn;
	struct stream *s;
	int finst;

	htxn = MAY_LJMP(hlua_checktxn(L, 1));

	/* If the flags NOTERM is set, we cannot terminate the session, so we
	 * just end the execution of the current lua code. */
	if (htxn->flags & HLUA_TXN_NOTERM)
		WILL_LJMP(hlua_done(L));

	s = htxn->s;
	if (!IS_HTX_STRM(htxn->s)) {
		struct channel *req = &s->req;
		struct channel *res = &s->res;

		channel_auto_read(req);
		channel_abort(req);
		channel_erase(req);

		channel_auto_read(res);
		channel_auto_close(res);
		sc_schedule_abort(s->scb);

		finst = ((htxn->dir == SMP_OPT_DIR_REQ) ? SF_FINST_R : SF_FINST_D);
		goto done;
	}

	if (lua_gettop(L) == 1 || !lua_istable(L, 2)) {
		/* No reply or invalid reply */
		s->txn->status = 0;
		http_reply_and_close(s, 0, NULL);
	}
	else {
		/* Remove extra args to have the reply on top of the stack */
		if (lua_gettop(L) > 2)
			lua_pop(L, lua_gettop(L) - 2);

		if (!hlua_txn_forward_reply(L, s)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_PRXCOND;
			lua_pushinteger(L, ACT_RET_ERR);
			WILL_LJMP(hlua_done(L));
			return 0; /* Never reached */
		}
	}

	finst = ((htxn->dir == SMP_OPT_DIR_REQ) ? SF_FINST_R : SF_FINST_H);
	if (htxn->dir == SMP_OPT_DIR_REQ) {
		/* let's log the request time */
		s->logs.request_ts = now_ns;
		if (s->sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_INC(&s->sess->fe->fe_counters.intercepted_req);
	}

  done:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;

	if ((htxn->flags & HLUA_TXN_CTX_MASK) == HLUA_TXN_FLT_CTX)
		lua_pushinteger(L, -1);
	else
		lua_pushinteger(L, ACT_RET_ABRT);
	WILL_LJMP(hlua_done(L));
	return 0;
}

/*
 *
 *
 * Class REPLY
 *
 *
 */

/* Pushes the TXN reply onto the top of the stack. If the stask does not have a
 * free slots, the function fails and returns 0;
 */
__LJMP static int hlua_txn_reply_new(lua_State *L)
{
	struct hlua_txn *htxn;
	const char *reason, *body = NULL;
	int ret, status;

	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	if (!IS_HTX_STRM(htxn->s)) {
		hlua_pusherror(L, "txn object is not an HTTP transaction.");
		WILL_LJMP(lua_error(L));
	}

	/* Default value */
	status = 200;
	reason = http_get_reason(status);

	if (lua_istable(L, 2)) {
		/* load status and reason from the table argument at index 2 */
		ret = lua_getfield(L, 2, "status");
		if (ret == LUA_TNIL)
			goto reason;
		else if (ret != LUA_TNUMBER) {
			/* invalid status: ignore the reason */
			goto body;
		}
		status = lua_tointeger(L, -1);

	  reason:
		lua_pop(L, 1); /* restore the stack: remove status */
		ret = lua_getfield(L, 2, "reason");
		if (ret == LUA_TSTRING)
			reason = lua_tostring(L, -1);

	  body:
		lua_pop(L, 1); /* restore the stack: remove invalid status or reason */
		ret = lua_getfield(L, 2, "body");
		if (ret == LUA_TSTRING)
			body = lua_tostring(L, -1);
		lua_pop(L, 1); /* restore the stack: remove  body */
	}

	/* Create the Reply table */
	lua_newtable(L);

	/* Add status element */
	lua_pushstring(L, "status");
	lua_pushinteger(L, status);
	lua_settable(L, -3);

	/* Add reason element */
	reason = http_get_reason(status);
	lua_pushstring(L, "reason");
	lua_pushstring(L, reason);
	lua_settable(L, -3);

	/* Add body element, nil if undefined */
	lua_pushstring(L, "body");
	if (body)
		lua_pushstring(L, body);
	else
		lua_pushnil(L);
	lua_settable(L, -3);

	/* Add headers element */
	lua_pushstring(L, "headers");
	lua_newtable(L);

	/* stack: [ txn, <Arg:table>, <Reply:table>, "headers", <headers:table> ] */
	if (lua_istable(L, 2)) {
		/* load headers from the table argument at index 2. If it is a table, copy it. */
		ret = lua_getfield(L, 2, "headers");
		if (ret == LUA_TTABLE) {
			/* stack: [ ... <headers:table>, <table> ] */
			lua_pushnil(L);
			while (lua_next(L, -2) != 0) {
				/* stack: [ ... <headers:table>, <table>, k, v] */
				if (!lua_isstring(L, -1) && !lua_istable(L, -1)) {
					/* invalid value type, skip it */
					lua_pop(L, 1);
					continue;
				}


				/* Duplicate the key and swap it with the value. */
				lua_pushvalue(L, -2);
				lua_insert(L, -2);
				/* stack: [ ... <headers:table>, <table>, k, k, v ] */

				lua_newtable(L);
				lua_insert(L, -2);
				/* stack: [ ... <headers:table>, <table>, k, k, <inner:table>, v ] */

				if (lua_isstring(L, -1)) {
					/* push the value in the inner table */
					lua_rawseti(L, -2, 1);
				}
				else { /* table */
					lua_pushnil(L);
					while (lua_next(L, -2) != 0) {
						/* stack: [ ... <headers:table>, <table>, k, k, <inner:table>, <v:table>, k2, v2 ] */
						if (!lua_isstring(L, -1)) {
							/* invalid value type, skip it*/
							lua_pop(L, 1);
							continue;
						}
						/* push the value in the inner table */
						lua_rawseti(L, -4, lua_rawlen(L, -4) + 1);
						/* stack: [ ... <headers:table>, <table>, k, k, <inner:table>, <v:table>, k2 ] */
					}
					lua_pop(L, 1);
					/* stack: [ ... <headers:table>, <table>, k, k, <inner:table> ] */
				}

				/* push (k,v) on the stack in the headers table:
				 * stack: [ ... <headers:table>, <table>, k, k, v ]
				 */
				lua_settable(L, -5);
				/* stack: [ ... <headers:table>, <table>, k ] */
			}
		}
		lua_pop(L, 1);
	}
	/* stack: [ txn, <Arg:table>, <Reply:table>, "headers", <headers:table> ] */
	lua_settable(L, -3);
	/* stack: [ txn, <Arg:table>, <Reply:table> ] */

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_txn_reply_ref);
	lua_setmetatable(L, -2);
	return 1;
}

/* Set the reply status code, and optionally the reason. If no reason is
 * provided, the default one corresponding to the status code is used.
 */
__LJMP static int hlua_txn_reply_set_status(lua_State *L)
{
	int status = MAY_LJMP(luaL_checkinteger(L, 2));
	const char *reason = MAY_LJMP(luaL_optlstring(L, 3, NULL, NULL));

	/* First argument (self) must be a table */
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));

	if (status < 100 || status > 599) {
		lua_pushboolean(L, 0);
		return 1;
	}
	if (!reason)
		reason = http_get_reason(status);

	lua_pushinteger(L, status);
	lua_setfield(L, 1, "status");

	lua_pushstring(L, reason);
	lua_setfield(L, 1, "reason");

	lua_pushboolean(L, 1);
	return 1;
}

/* Add a header into the reply object. Each header name is associated to an
 * array of values in the "headers" table. If the header name is not found, a
 * new entry is created.
 */
__LJMP static int hlua_txn_reply_add_header(lua_State *L)
{
	const char *name = MAY_LJMP(luaL_checkstring(L, 2));
	const char *value = MAY_LJMP(luaL_checkstring(L, 3));
	int ret;

	/* First argument (self) must be a table */
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));

	/* Push in the stack the "headers" entry. */
	ret = lua_getfield(L, 1, "headers");
	if (ret != LUA_TTABLE) {
		hlua_pusherror(L, "Reply['headers'] is expected to a an array. %s found", lua_typename(L, ret));
		WILL_LJMP(lua_error(L));
	}

	/* check if the header is already registered. If not, register it. */
	ret = lua_getfield(L, -1, name);
	if (ret == LUA_TNIL) {
		/* Entry not found. */
		lua_pop(L, 1); /* remove the nil. The "headers" table is the top of the stack. */

		/* Insert the new header name in the array in the top of the stack.
		 * It left the new array in the top of the stack.
		 */
		lua_newtable(L);
		lua_pushstring(L, name);
		lua_pushvalue(L, -2);
		lua_settable(L, -4);
	}
	else if (ret != LUA_TTABLE) {
		hlua_pusherror(L, "Reply['headers']['%s'] is expected to be an array. %s found", name, lua_typename(L, ret));
		WILL_LJMP(lua_error(L));
	}

	/* Now the top of thestack is an array of values. We push
	 * the header value as new entry.
	 */
	lua_pushstring(L, value);
	ret = lua_rawlen(L, -2);
	lua_rawseti(L, -2, ret + 1);

	lua_pushboolean(L, 1);
	return 1;
}

/* Remove all occurrences of a given header name. */
__LJMP static int hlua_txn_reply_del_header(lua_State *L)
{
	const char *name = MAY_LJMP(luaL_checkstring(L, 2));
	int ret;

	/* First argument (self) must be a table */
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));

	/* Push in the stack the "headers" entry. */
	ret = lua_getfield(L, 1, "headers");
	if (ret != LUA_TTABLE) {
		hlua_pusherror(L, "Reply['headers'] is expected to be an array. %s found", lua_typename(L, ret));
		WILL_LJMP(lua_error(L));
	}

	lua_pushstring(L, name);
	lua_pushnil(L);
	lua_settable(L, -3);

	lua_pushboolean(L, 1);
	return 1;
}

/* Set the reply's body. Overwrite any existing entry. */
__LJMP static int hlua_txn_reply_set_body(lua_State *L)
{
	const char *payload = MAY_LJMP(luaL_checkstring(L, 2));

	/* First argument (self) must be a table */
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));

	lua_pushstring(L, payload);
	lua_setfield(L, 1, "body");

	lua_pushboolean(L, 1);
	return 1;
}

__LJMP static int hlua_log(lua_State *L)
{
	int level;
	const char *msg;

	MAY_LJMP(check_args(L, 2, "log"));
	level = MAY_LJMP(luaL_checkinteger(L, 1));
	msg = MAY_LJMP(luaL_checkstring(L, 2));

	if (level < 0 || level >= NB_LOG_LEVELS)
		WILL_LJMP(luaL_argerror(L, 1, "Invalid loglevel."));

	hlua_sendlog(NULL, level, msg);
	return 0;
}

__LJMP static int hlua_log_debug(lua_State *L)
{
	const char *msg;

	MAY_LJMP(check_args(L, 1, "debug"));
	msg = MAY_LJMP(luaL_checkstring(L, 1));
	hlua_sendlog(NULL, LOG_DEBUG, msg);
	return 0;
}

__LJMP static int hlua_log_info(lua_State *L)
{
	const char *msg;

	MAY_LJMP(check_args(L, 1, "info"));
	msg = MAY_LJMP(luaL_checkstring(L, 1));
	hlua_sendlog(NULL, LOG_INFO, msg);
	return 0;
}

__LJMP static int hlua_log_warning(lua_State *L)
{
	const char *msg;

	MAY_LJMP(check_args(L, 1, "warning"));
	msg = MAY_LJMP(luaL_checkstring(L, 1));
	hlua_sendlog(NULL, LOG_WARNING, msg);
	return 0;
}

__LJMP static int hlua_log_alert(lua_State *L)
{
	const char *msg;

	MAY_LJMP(check_args(L, 1, "alert"));
	msg = MAY_LJMP(luaL_checkstring(L, 1));
	hlua_sendlog(NULL, LOG_ALERT, msg);
	return 0;
}

__LJMP static int hlua_sleep_yield(lua_State *L, int status, lua_KContext ctx)
{
	int wakeup_ms = lua_tointeger(L, -1);
	if (!tick_is_expired(wakeup_ms, now_ms))
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

__LJMP static int hlua_sleep(lua_State *L)
{
	unsigned int delay;
	int wakeup_ms; // tick value

	MAY_LJMP(check_args(L, 1, "sleep"));

	delay = MAY_LJMP(luaL_checkinteger(L, 1)) * 1000;
	wakeup_ms = tick_add(now_ms, delay);
	lua_pushinteger(L, wakeup_ms);

	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

__LJMP static int hlua_msleep(lua_State *L)
{
	unsigned int delay;
	int wakeup_ms; // tick value

	MAY_LJMP(check_args(L, 1, "msleep"));

	delay = MAY_LJMP(luaL_checkinteger(L, 1));
	wakeup_ms = tick_add(now_ms, delay);
	lua_pushinteger(L, wakeup_ms);

	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

/* This functionis an LUA binding. it permits to give back
 * the hand at the HAProxy scheduler. It is used when the
 * LUA processing consumes a lot of time.
 */
__LJMP static int hlua_yield_yield(lua_State *L, int status, lua_KContext ctx)
{
	return 0;
}

__LJMP static int hlua_yield(lua_State *L)
{
	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_yield_yield, TICK_ETERNITY, HLUA_CTRLYIELD));
	return 0;
}

/* This function change the nice of the currently executed
 * task. It is used set low or high priority at the current
 * task.
 */
__LJMP static int hlua_set_nice(lua_State *L)
{
	struct hlua *hlua;
	int nice;

	MAY_LJMP(check_args(L, 1, "set_nice"));
	nice = MAY_LJMP(luaL_checkinteger(L, 1));

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);

	/* If the task is not set, I'm in a start mode. */
	if (!hlua || !hlua->task)
		return 0;

	if (nice < -1024)
		nice = -1024;
	else if (nice > 1024)
		nice = 1024;

	hlua->task->nice = nice;
	return 0;
}

/* safe lua coroutine.create() function:
 *
 * This is a simple wrapper for coroutine.create() that
 * ensures the current hlua state ctx is available from
 * the new subroutine state
 */
__LJMP static int hlua_coroutine_create(lua_State *L)
{
	lua_State *new; /* new coroutine state */
	struct hlua **hlua_store;
	struct hlua *hlua = hlua_gethlua(L);

	new = lua_newthread(L);
	if (!new)
		return 0;

	hlua_store = lua_getextraspace(new);
	/* Expose current hlua ctx on new lua thread
	 * (hlua_gethlua() will properly return the last "known"
	 *  hlua ctx instead of NULL when it is called from such coroutines)
	 */
	*hlua_store = hlua;

	/* new lua thread is on the top of the stack, we
	 * need to duplicate first stack argument (<f> from coroutine.create(<f>))
	 * on the top of the stack to be able to use xmove() to move it on the new
	 * stack
	 */
	lua_pushvalue(L, 1);
	/* move <f> function to the new stack */
	lua_xmove(L, new, 1);
	/* new lua thread is back at the top of the stack */
	return 1;
}

/* This function is used as a callback of a task. It is called by the
 * HAProxy task subsystem when the task is awaked. The LUA runtime can
 * return an E_AGAIN signal, the emmiter of this signal must set a
 * signal to wake the task.
 *
 * Task wrapper are longjmp safe because the only one Lua code
 * executed is the safe hlua_ctx_resume();
 */
struct task *hlua_process_task(struct task *task, void *context, unsigned int state)
{
	struct hlua *hlua = context;
	enum hlua_exec status;

	if (task->tid < 0)
		task->tid = tid;

	/* If it is the first call to the task, we must initialize the
	 * execution timeouts.
	 */
	if (!HLUA_IS_RUNNING(hlua))
		hlua_timer_init(&hlua->timer, hlua_timeout_task);

	/* Execute the Lua code. */
	status = hlua_ctx_resume(hlua, 1);

	switch (status) {
	/* finished or yield */
	case HLUA_E_OK:
		hlua_ctx_destroy(hlua);
		task_destroy(task);
		task = NULL;
		break;

	case HLUA_E_AGAIN: /* co process or timeout wake me later. */
		notification_gc(&hlua->com);
		task->expire = hlua->wake_time;
		break;

	/* finished with error. */
	case HLUA_E_ETMOUT:
		SEND_ERR(NULL, "Lua task: execution timeout.\n");
		goto err_task_abort;
	case HLUA_E_BTMOUT:
		SEND_ERR(NULL, "Lua task: burst timeout.\n");
		goto err_task_abort;
	case HLUA_E_ERRMSG:
		hlua_lock(hlua);
		SEND_ERR(NULL, "Lua task: %s.\n", hlua_tostring_safe(hlua->T, -1));
		hlua_unlock(hlua);
		goto err_task_abort;
	case HLUA_E_ERR:
	default:
		SEND_ERR(NULL, "Lua task: unknown error.\n");
	err_task_abort:
		hlua_ctx_destroy(hlua);
		task_destroy(task);
		task = NULL;
		break;
	}
	return task;
}

/* This function is an LUA binding that register LUA function to be
 * executed after the HAProxy configuration parsing and before the
 * HAProxy scheduler starts. This function expect only one LUA
 * argument that is a function. This function returns nothing, but
 * throws if an error is encountered.
 */
__LJMP static int hlua_register_init(lua_State *L)
{
	struct hlua_init_function *init;
	int ref;

	MAY_LJMP(check_args(L, 1, "register_init"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_init: not available outside of body context"));
	}

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	init = calloc(1, sizeof(*init));
	if (!init) {
		hlua_unref(L, ref);
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	}

	init->function_ref = ref;
	LIST_APPEND(&hlua_init_functions[hlua_state_id], &init->l);
	return 0;
}

/* This function is an LUA binding. It permits to register a task
 * executed in parallel of the main HAroxy activity. The task is
 * created and it is set in the HAProxy scheduler. It can be called
 * from the "init" section, "post init" or during the runtime.
 *
 * Lua prototype:
 *
 *   <none> core.register_task(<function>[, <arg1>[, <arg2>[, ...[, <arg4>]]]])
 *
 * <arg1..4> are optional arguments that will be provided to <function>
 */
__LJMP static int hlua_register_task(lua_State *L)
{
	struct hlua *hlua = NULL;
	struct task *task = NULL;
	int ref;
	int nb_arg;
	int it;
	int arg_ref[4]; /* optional arguments */
	int state_id;

	nb_arg = lua_gettop(L);
	if (nb_arg < 1)
		WILL_LJMP(luaL_error(L, "register_task: <func> argument is required"));
	else if (nb_arg > 5)
		WILL_LJMP(luaL_error(L, "register_task: no more that 4 optional arguments may be provided"));

	/* first arg: function ref */
	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	/* extract optional args (if any) */
	it = 0;
	while (--nb_arg) {
		lua_pushvalue(L, 2 + it);
		arg_ref[it] = hlua_ref(L); /* get arg reference */
		it += 1;
	}
	nb_arg = it;

	/* Get the reference state. If the reference is NULL, L is the master
	 * state, otherwise hlua->T is.
	 */
	hlua = hlua_gethlua(L);
	if (hlua)
		/* we are in runtime processing */
		state_id = hlua->state_id;
	else
		/* we are in initialization mode */
		state_id = hlua_state_id;

	hlua = pool_alloc(pool_head_hlua);
	if (!hlua)
		goto alloc_error;
	HLUA_INIT(hlua);

	/* We are in the common lua state, execute the task anywhere,
	 * otherwise, inherit the current thread identifier
	 */
	if (state_id == 0)
		task = task_new_anywhere();
	else
		task = task_new_here();
	if (!task)
		goto alloc_error;

	task->context = hlua;
	task->process = hlua_process_task;

	if (!hlua_ctx_init(hlua, state_id, task))
		goto alloc_error;

	/* Ensure there is enough space on the stack for the function
	 * plus optional arguments
	 */
	if (!lua_checkstack(hlua->T, (1 + nb_arg)))
		goto alloc_error;

	/* Restore the function in the stack. */
	hlua_pushref(hlua->T, ref);
	/* function ref not needed anymore since it was pushed to the substack */
	hlua_unref(L, ref);

	hlua->nargs = nb_arg;

	/* push optional arguments to the function */
	for (it = 0; it < nb_arg; it++) {
		/* push arg to the stack */
		hlua_pushref(hlua->T, arg_ref[it]);
		/* arg ref not needed anymore since it was pushed to the substack */
		hlua_unref(L, arg_ref[it]);
	}

	/* Schedule task. */
	task_wakeup(task, TASK_WOKEN_INIT);

	return 0;

  alloc_error:
	task_destroy(task);
	hlua_unref(L, ref);
	for (it = 0; it < nb_arg; it++) {
		hlua_unref(L, arg_ref[it]);
	}
	hlua_ctx_destroy(hlua);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

/* called from unsafe location */
static void hlua_event_subscription_destroy(struct hlua_event_sub *hlua_sub)
{
	/* hlua cleanup */

	hlua_lock(hlua_sub->hlua);
	/* registry is shared between coroutines */
	hlua_unref(hlua_sub->hlua->T, hlua_sub->fcn_ref);
	hlua_unlock(hlua_sub->hlua);

	hlua_ctx_destroy(hlua_sub->hlua);

	/* free */
	pool_free(pool_head_hlua_event_sub, hlua_sub);
}

/* single event handler: hlua ctx is shared between multiple events handlers
 * issued from the same subscription. Thus, it is not destroyed when the event
 * is processed: it is destroyed when no more events are expected for the
 * subscription (ie: when the subscription ends).
 *
 * Moreover, events are processed sequentially within the subscription:
 * one event must be fully processed before another one may be processed.
 * This ensures proper consistency for lua event handling from an ordering
 * point of view. This is especially useful with server events for example
 * where ADD/DEL/UP/DOWN events ordering really matters to trigger specific
 * actions from lua (e.g.: sending emails or making API calls).
 *
 * Due to this design, each lua event handler is pleased to process the event
 * as fast as possible to prevent the event queue from growing up.
 * Strictly speaking, there is no runtime limit for the callback function
 * (timeout set to default task timeout), but if the event queue goes past
 * the limit of unconsumed events an error will be reported and the
 * susbscription will pause itself for as long as it takes for the handler to
 * catch up (events will be lost as a result).
 * If the event handler does not need the sequential ordering and wants to
 * process multiple events at a time, it may spawn a new side-task using
 * 'core.register_task' to delegate the event handling and make parallel event
 * processing within the same subscription set.
 */
static void hlua_event_handler(struct hlua *hlua)
{
	enum hlua_exec status;

	/* If it is the first call to the task, we must initialize the
	 * execution timeouts.
	 */
	if (!HLUA_IS_RUNNING(hlua))
		hlua_timer_init(&hlua->timer, hlua_timeout_task);

	/* make sure to reset the task expiry before each hlua_ctx_resume()
	 * since the task is re-used for multiple cb function calls
	 * We couldn't risk to have t->expire pointing to a past date because
	 * it was set during last function invocation but was never reset since
	 * (ie: E_AGAIN)
	 */
	hlua->task->expire = TICK_ETERNITY;

	/* Execute the Lua code. */
	status = hlua_ctx_resume(hlua, 1);

	switch (status) {
	/* finished or yield */
	case HLUA_E_OK:
		break;

	case HLUA_E_AGAIN: /* co process or timeout wake me later. */
		notification_gc(&hlua->com);
		hlua->task->expire = hlua->wake_time;
		break;

	/* finished with error. */
	case HLUA_E_ETMOUT:
		SEND_ERR(NULL, "Lua event_hdl: execution timeout.\n");
		break;

	case HLUA_E_BTMOUT:
		SEND_ERR(NULL, "Lua event_hdl: burst timeout.\n");
		break;

	case HLUA_E_ERRMSG:
		hlua_lock(hlua);
		SEND_ERR(NULL, "Lua event_hdl: %s.\n", hlua_tostring_safe(hlua->T, -1));
		hlua_unlock(hlua);
		break;

	case HLUA_E_ERR:
	default:
		SEND_ERR(NULL, "Lua event_hdl: unknown error.\n");
		break;
	}
}

__LJMP static void hlua_event_hdl_cb_push_event_checkres(lua_State *L,
                                                         struct event_hdl_cb_data_server_checkres *check)
{
	lua_pushstring(L, "agent");
	lua_pushboolean(L, check->agent);
	lua_settable(L, -3);
	lua_pushstring(L, "result");
	switch (check->result) {
		case CHK_RES_FAILED:
			lua_pushstring(L, "FAILED");
			break;
		case CHK_RES_PASSED:
			lua_pushstring(L, "PASSED");
			break;
		case CHK_RES_CONDPASS:
			lua_pushstring(L, "CONDPASS");
			break;
		default:
			lua_pushnil(L);
			break;
	}
	lua_settable(L, -3);

	lua_pushstring(L, "duration");
	lua_pushinteger(L, check->duration);
	lua_settable(L, -3);

	lua_pushstring(L, "reason");
	lua_newtable(L);

	lua_pushstring(L, "short");
	lua_pushstring(L, get_check_status_info(check->reason.status));
	lua_settable(L, -3);
	lua_pushstring(L, "desc");
	lua_pushstring(L, get_check_status_description(check->reason.status));
	lua_settable(L, -3);
	if (check->reason.status >= HCHK_STATUS_L57DATA) {
		/* code only available when the check reached data analysis stage */
		lua_pushstring(L, "code");
		lua_pushinteger(L, check->reason.code);
		lua_settable(L, -3);
	}

	lua_settable(L, -3); /* reason table */

	lua_pushstring(L, "health");
	lua_newtable(L);

	lua_pushstring(L, "cur");
	lua_pushinteger(L, check->health.cur);
	lua_settable(L, -3);
	lua_pushstring(L, "rise");
	lua_pushinteger(L, check->health.rise);
	lua_settable(L, -3);
	lua_pushstring(L, "fall");
	lua_pushinteger(L, check->health.fall);
	lua_settable(L, -3);

	lua_settable(L, -3); /* health table */
}

/* This function pushes various arguments such as event type and event data to
 * the lua function that will be called to consume the event.
 */
__LJMP static void hlua_event_hdl_cb_push_args(struct hlua_event_sub *hlua_sub,
                                               struct event_hdl_async_event *e)
{
	struct hlua *hlua = hlua_sub->hlua;
	struct event_hdl_sub_type event = e->type;
	void *data = e->data;

	/* push event type */
	hlua->nargs = 1;
	lua_pushstring(hlua->T, event_hdl_sub_type_to_string(event));

	/* push event data (according to event type) */
	if (event_hdl_sub_family_equal(EVENT_HDL_SUB_SERVER, event)) {
		struct event_hdl_cb_data_server *e_server = data;
		struct proxy *px;
		struct server *server;

		hlua->nargs += 1;
		lua_newtable(hlua->T);
		/* Add server name */
		lua_pushstring(hlua->T, "name");
		lua_pushstring(hlua->T, e_server->safe.name);
		lua_settable(hlua->T, -3);
		/* Add server puid */
		lua_pushstring(hlua->T, "puid");
		lua_pushinteger(hlua->T, e_server->safe.puid);
		lua_settable(hlua->T, -3);
		/* Add server rid */
		lua_pushstring(hlua->T, "rid");
		lua_pushinteger(hlua->T, e_server->safe.rid);
		lua_settable(hlua->T, -3);
		/* Add server proxy name */
		lua_pushstring(hlua->T, "proxy_name");
		lua_pushstring(hlua->T, e_server->safe.proxy_name);
		lua_settable(hlua->T, -3);
		/* Add server proxy uuid */
		lua_pushstring(hlua->T, "proxy_uuid");
		lua_pushinteger(hlua->T, e_server->safe.proxy_uuid);
		lua_settable(hlua->T, -3);

		/* special events, fetch additional info with explicit type casting */
		if (event_hdl_sub_type_equal(EVENT_HDL_SUB_SERVER_STATE, event)) {
			struct event_hdl_cb_data_server_state *state = data;
			int it;

			if (!lua_checkstack(hlua->T, 20))
				WILL_LJMP(luaL_error(hlua->T, "Lua out of memory error."));

			/* state subclass */
			lua_pushstring(hlua->T, "state");
			lua_newtable(hlua->T);

			lua_pushstring(hlua->T, "admin");
			lua_pushboolean(hlua->T, state->safe.type);
			lua_settable(hlua->T, -3);

			/* is it because of a check ? */
			if (!state->safe.type &&
			    (state->safe.op_st_chg.cause == SRV_OP_STCHGC_HEALTH ||
			     state->safe.op_st_chg.cause == SRV_OP_STCHGC_AGENT)) {
				/* yes, provide check result */
				lua_pushstring(hlua->T, "check");
				lua_newtable(hlua->T);
				hlua_event_hdl_cb_push_event_checkres(hlua->T, &state->safe.op_st_chg.check);
				lua_settable(hlua->T, -3); /* check table */
			}

			lua_pushstring(hlua->T, "cause");
			if (state->safe.type)
				lua_pushstring(hlua->T, srv_adm_st_chg_cause(state->safe.adm_st_chg.cause));
			else
				lua_pushstring(hlua->T, srv_op_st_chg_cause(state->safe.op_st_chg.cause));
			lua_settable(hlua->T, -3);

			/* old_state, new_state */
			for (it = 0; it < 2; it++) {
				enum srv_state srv_state = (!it) ? state->safe.old_state : state->safe.new_state;

				lua_pushstring(hlua->T, (!it) ? "old_state" : "new_state");
				switch (srv_state) {
					case SRV_ST_STOPPED:
						lua_pushstring(hlua->T, "STOPPED");
						break;
					case SRV_ST_STOPPING:
						lua_pushstring(hlua->T, "STOPPING");
						break;
					case SRV_ST_STARTING:
						lua_pushstring(hlua->T, "STARTING");
						break;
					case SRV_ST_RUNNING:
						lua_pushstring(hlua->T, "RUNNING");
						break;
					default:
						lua_pushnil(hlua->T);
						break;
				}
				lua_settable(hlua->T, -3);
			}

			/* requeued */
			lua_pushstring(hlua->T, "requeued");
			lua_pushinteger(hlua->T, state->safe.requeued);
			lua_settable(hlua->T, -3);

			lua_settable(hlua->T, -3); /* state table */
		}
		else if (event_hdl_sub_type_equal(EVENT_HDL_SUB_SERVER_ADMIN, event)) {
			struct event_hdl_cb_data_server_admin *admin = data;
			int it;

			if (!lua_checkstack(hlua->T, 20))
				WILL_LJMP(luaL_error(hlua->T, "Lua out of memory error."));

			/* admin subclass */
			lua_pushstring(hlua->T, "admin");
			lua_newtable(hlua->T);

			lua_pushstring(hlua->T, "cause");
			lua_pushstring(hlua->T, srv_adm_st_chg_cause(admin->safe.cause));
			lua_settable(hlua->T, -3);

			/* old_admin, new_admin */
			for (it = 0; it < 2; it++) {
				enum srv_admin srv_admin = (!it) ? admin->safe.old_admin : admin->safe.new_admin;

				lua_pushstring(hlua->T, (!it) ? "old_admin" : "new_admin");

				/* admin state matrix */
				lua_newtable(hlua->T);

				lua_pushstring(hlua->T, "MAINT");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_MAINT);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "FMAINT");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_FMAINT);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "IMAINT");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_IMAINT);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "RMAINT");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_RMAINT);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "CMAINT");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_CMAINT);
				lua_settable(hlua->T, -3);

				lua_pushstring(hlua->T, "DRAIN");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_DRAIN);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "FDRAIN");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_FDRAIN);
				lua_settable(hlua->T, -3);
				lua_pushstring(hlua->T, "IDRAIN");
				lua_pushboolean(hlua->T, srv_admin & SRV_ADMF_IDRAIN);
				lua_settable(hlua->T, -3);

				lua_settable(hlua->T, -3); /* matrix table */
			}
			/* requeued */
			lua_pushstring(hlua->T, "requeued");
			lua_pushinteger(hlua->T, admin->safe.requeued);
			lua_settable(hlua->T, -3);

			lua_settable(hlua->T, -3); /* admin table */
		}
		else if (event_hdl_sub_type_equal(EVENT_HDL_SUB_SERVER_CHECK, event)) {
			struct event_hdl_cb_data_server_check *check = data;

			if (!lua_checkstack(hlua->T, 20))
				WILL_LJMP(luaL_error(hlua->T, "Lua out of memory error."));

			/* check subclass */
			lua_pushstring(hlua->T, "check");
			lua_newtable(hlua->T);

			/* check result snapshot */
			hlua_event_hdl_cb_push_event_checkres(hlua->T, &check->safe.res);

			lua_settable(hlua->T, -3); /* check table */
		}

		/* attempt to provide reference server object
		 * (if it wasn't removed yet, SERVER_DEL will never succeed here)
		 */
		px = proxy_find_by_id(e_server->safe.proxy_uuid, PR_CAP_BE, 0);
		BUG_ON(!px);
		server = server_find_by_id_unique(px, e_server->safe.puid, e_server->safe.rid);
		if (server) {
			lua_pushstring(hlua->T, "reference");
			hlua_fcn_new_server(hlua->T, server);
			lua_settable(hlua->T, -3);
		}
	}
	/* sub mgmt */
	hlua->nargs += 1;
	hlua_fcn_new_event_sub(hlua->T, hlua_sub->sub);

	/* when? */
	hlua->nargs += 1;
	lua_pushinteger(hlua->T, e->when.tv_sec);
}

/* events runner: if there's an ongoing hlua event handling process, finish it
 * then, check if there are new events waiting to be processed
 * (events are processed sequentially)
 *
 * We have a safety measure to warn/guard if the event queue is growing up
 * too much due to many events being generated and lua handler is unable to
 * keep up the pace (e.g.: when the event queue grows past 100 unconsumed events).
 * TODO: make it tunable
 */
static struct task *hlua_event_runner(struct task *task, void *context, unsigned int state)
{
	struct hlua_event_sub *hlua_sub = context;
	struct event_hdl_async_event *event;
	const char *error = NULL;

	if (!hlua_sub->paused && event_hdl_async_equeue_size(&hlua_sub->equeue) > 100) {
		const char *trace = NULL;

		/* We reached the limit of pending events in the queue: we should
		 * warn the user, and temporarily pause the subscription to give a chance
		 * to the handler to catch up? (it also prevents resource shortage since
		 * the queue could grow indefinitely otherwise)
		 * TODO: find a way to inform the handler that it missed some events
		 * (example: stats within the subscription in event_hdl api exposed via lua api?)
		 *
		 * Nonetheless, reaching this limit means that the handler is not fast enough
		 * and/or that it subscribed to events that happen too frequently and did not
		 * expect it. This could come from an inadequate design in the user's script.
		 */
		event_hdl_pause(hlua_sub->sub);
		hlua_sub->paused = 1;

		trace = hlua_traceback(hlua_sub->hlua->T, ", ");

		ha_warning("Lua event_hdl: pausing the subscription because the handler fails "
			   "to keep up the pace (%u unconsumed events) from %s.\n",
			   event_hdl_async_equeue_size(&hlua_sub->equeue), trace);
	}

	if (HLUA_IS_RUNNING(hlua_sub->hlua)) {
		/* ongoing hlua event handler, resume it */
		hlua_event_handler(hlua_sub->hlua);
	} else if ((event = event_hdl_async_equeue_pop(&hlua_sub->equeue))) { /* check for new events */
		if (event_hdl_sub_type_equal(event->type, EVENT_HDL_SUB_END)) {
			/* ending event: no more events to come */
			event_hdl_async_free_event(event);
			task_destroy(task);
			hlua_event_subscription_destroy(hlua_sub);
			return NULL;
		}
		/* new event: start processing it */

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua_sub->hlua)) {
			hlua_lock(hlua_sub->hlua);
			if (lua_type(hlua_sub->hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua_sub->hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(NULL, "Lua event_hdl: %s.\n", error);
			hlua_unlock(hlua_sub->hlua);
			goto skip_event;
		}

		/* Check stack available size. */
		if (!lua_checkstack(hlua_sub->hlua->T, 5)) {
			SEND_ERR(NULL, "Lua event_hdl: full stack.\n");
			RESET_SAFE_LJMP(hlua_sub->hlua);
			goto skip_event;
		}

		/* Restore the function in the stack. */
		hlua_pushref(hlua_sub->hlua->T, hlua_sub->fcn_ref);

		/* push args */
		hlua_sub->hlua->nargs = 0;
		MAY_LJMP(hlua_event_hdl_cb_push_args(hlua_sub, event));

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(hlua_sub->hlua);

		/* At this point the event was successfully translated into hlua ctx,
		 * or hlua error occurred, so we can safely discard it
		 */
		event_hdl_async_free_event(event);
		event = NULL;

		hlua_event_handler(hlua_sub->hlua);
 skip_event:
		if (event)
			event_hdl_async_free_event(event);

	}

	if (!HLUA_IS_RUNNING(hlua_sub->hlua)) {
		/* we just finished the processing of one event..
		 * check for new events before becoming idle
		 */
		if (!event_hdl_async_equeue_isempty(&hlua_sub->equeue)) {
			/* more events to process, make sure the task
			 * will be resumed ASAP to process pending events
			 */
			task_wakeup(task, TASK_WOKEN_OTHER);
		}
		else if (hlua_sub->paused) {
			/* empty queue, the handler caught up: resume the subscription */
			event_hdl_resume(hlua_sub->sub);
			hlua_sub->paused = 0;
		}
	}

	return task;
}

/* Must be called directly under lua protected/safe environment
 * (not from external callback)
 * <fcn_ref> should NOT be dropped after the function successfully returns:
 * it will be done automatically in hlua_event_subscription_destroy() when the
 * subscription ends.
 *
 * Returns the new subscription on success and NULL on failure (memory error)
 */
static struct event_hdl_sub *hlua_event_subscribe(event_hdl_sub_list *list, struct event_hdl_sub_type e_type,
                                                  int state_id, int fcn_ref)
{
	struct hlua_event_sub *hlua_sub;
	struct task *task = NULL;

	hlua_sub = pool_alloc(pool_head_hlua_event_sub);
	if (!hlua_sub)
		goto mem_error;
	hlua_sub->task = NULL;
	hlua_sub->hlua = NULL;
	hlua_sub->paused = 0;
	if ((task = task_new_here()) == NULL)
		goto mem_error;
	task->process = hlua_event_runner;
	task->context = hlua_sub;
	event_hdl_async_equeue_init(&hlua_sub->equeue);
	hlua_sub->task = task;
	hlua_sub->fcn_ref = fcn_ref;
	hlua_sub->state_id = state_id;
	hlua_sub->hlua = pool_alloc(pool_head_hlua);
	if (!hlua_sub->hlua)
		goto mem_error;
	HLUA_INIT(hlua_sub->hlua);
	if (!hlua_ctx_init(hlua_sub->hlua, hlua_sub->state_id, task))
		goto mem_error;

	hlua_sub->sub = event_hdl_subscribe_ptr(list, e_type,
	                                        EVENT_HDL_ASYNC_TASK(&hlua_sub->equeue,
	                                                             task,
	                                                             hlua_sub,
	                                                             NULL));
	if (!hlua_sub->sub)
		goto mem_error;

	return hlua_sub->sub; /* returns pointer to event_hdl_sub struct */

 mem_error:
	if (hlua_sub) {
		task_destroy(hlua_sub->task);
		if (hlua_sub->hlua)
			hlua_ctx_destroy(hlua_sub->hlua);
		pool_free(pool_head_hlua_event_sub, hlua_sub);
	}

	return NULL;
}

/* looks for an array of strings referring to a composition of event_hdl subscription
 * types at <index> in <L> stack
 */
__LJMP static struct event_hdl_sub_type hlua_check_event_sub_types(lua_State *L, int index)
{
	struct event_hdl_sub_type subscriptions;
	const char *msg;

	if (lua_type(L, index) != LUA_TTABLE) {
		msg = lua_pushfstring(L, "table of strings expected, got %s", luaL_typename(L, index));
		luaL_argerror(L, index, msg);
	}

	subscriptions = EVENT_HDL_SUB_NONE;

	/* browse the argument as an array. */
	lua_pushnil(L);
	while (lua_next(L, index) != 0) {
		if (lua_type(L, -1) != LUA_TSTRING) {
			msg = lua_pushfstring(L, "table of strings expected, got %s", luaL_typename(L, index));
			luaL_argerror(L, index, msg);
		}

		if (event_hdl_sub_type_equal(EVENT_HDL_SUB_NONE, event_hdl_string_to_sub_type(lua_tostring(L, -1)))) {
			msg = lua_pushfstring(L, "'%s' event type is unknown", lua_tostring(L, -1));
			luaL_argerror(L, index, msg);
		}

		/* perform subscriptions |= current sub */
		subscriptions = event_hdl_sub_type_add(subscriptions, event_hdl_string_to_sub_type(lua_tostring(L, -1)));

		/* pop the current value. */
		lua_pop(L, 1);
	}

	return subscriptions;
}

/* Wrapper for hlua_fcn_new_event_sub(): catch errors raised by
 * the function to prevent LJMP
 *
 * If no error occurred, the function returns 1, else it returns 0 and
 * the error message is pushed at the top of the stack
 */
__LJMP static int _hlua_new_event_sub_safe(lua_State *L)
{
	struct event_hdl_sub *sub = lua_touserdata(L, 1);

	/* this function may raise errors */
	return MAY_LJMP(hlua_fcn_new_event_sub(L, sub));
}
static int hlua_new_event_sub_safe(lua_State *L, struct event_hdl_sub *sub)
{
	if (!lua_checkstack(L, 2))
		return 0;
	lua_pushcfunction(L, _hlua_new_event_sub_safe);
	lua_pushlightuserdata(L, sub);
	switch (lua_pcall(L, 1, 1, 0)) {
		case LUA_OK:
			return 1;
		default:
			/* error was caught */
			return 0;
	}
}

/* This function is a LUA helper used for registering lua event callbacks.
 * It expects an event subscription array and the function to be executed
 * when subscribed events occur (stack arguments).
 * It can be called from the "init" section, "post init" or during the runtime.
 *
 * <sub_list> is the subscription list where the subscription will be attempted
 *
 * Pushes the newly allocated subscription on the stack on success
 */
__LJMP int hlua_event_sub(lua_State *L, event_hdl_sub_list *sub_list)
{
	struct hlua *hlua;
	struct event_hdl_sub *sub;
	struct event_hdl_sub_type subscriptions;
	int fcn_ref;
	int state_id;

	MAY_LJMP(check_args(L, 2, "event_sub"));

	/* Get the reference state */
	hlua = hlua_gethlua(L);
	if (hlua)
		/* we are in runtime processing, any thread may subscribe to events:
		 * subscription events will be handled by the thread who performed
		 * the registration.
		 */
		state_id = hlua->state_id;
	else {
		/* we are in initialization mode, only thread 0 (actual calling thread)
		 * may subscribe to events to prevent the same handler (from different lua
		 * stacks) from being registered multiple times
		 *
		 * hlua_state_id == 0: monostack (lua-load)
		 * hlua_state_id > 0: hlua_state_id=tid+1, multi-stack (lua-load-per-thread)
		 * (thus if hlua_state_id > 1, it means we are not in primary thread ctx)
		 */
		if (hlua_state_id > 1)
			return 0; /* skip registration */
		state_id = hlua_state_id;
	}

	/* First argument : event subscriptions. */
	subscriptions = MAY_LJMP(hlua_check_event_sub_types(L, 1));

	if (event_hdl_sub_type_equal(subscriptions, EVENT_HDL_SUB_NONE)) {
		WILL_LJMP(luaL_error(L, "event_sub: no valid event types were provided"));
		return 0; /* Never reached */
	}

	/* Second argument : lua function. */
	fcn_ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* try to subscribe */
	sub = hlua_event_subscribe(sub_list, subscriptions, state_id, fcn_ref);
	if (!sub) {
		hlua_unref(L, fcn_ref);
		WILL_LJMP(luaL_error(L, "event_sub: lua out of memory error"));
		return 0; /* Never reached */
	}

	/* push the subscription to the stack
	 *
	 * Here we use the safe function so that lua errors will be
	 * handled explicitly to prevent 'sub' from being lost
	 */
	if (!hlua_new_event_sub_safe(L, sub)) {
		/* Some events could already be pending in the handler's queue.
		 * However it is wiser to cancel the subscription since we are unable to
		 * provide a valid reference to it.
		 * Pending events will be delivered (unless lua keeps raising errors).
		 */
		event_hdl_unsubscribe(sub); /* cancel the subscription */
		WILL_LJMP(luaL_error(L, "event_sub: cannot push the subscription (%s)", lua_tostring(L, -1)));
		return 0; /* Never reached */
	}
	event_hdl_drop(sub); /* sub has been duplicated, discard old ref */

	return 1;
}

/* This function is a LUA wrapper used for registering global lua event callbacks
 * The new subscription is pushed onto the stack on success
 * Returns the number of arguments pushed to the stack (1 for success)
 */
__LJMP static int hlua_event_global_sub(lua_State *L)
{
	/* NULL <sub_list> = global subscription list */
	return MAY_LJMP(hlua_event_sub(L, NULL));
}

/* Wrapper called by HAProxy to execute an LUA converter. This wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume converters.
 */
static int hlua_sample_conv_wrapper(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct hlua_function *fcn = private;
	struct stream *stream = smp->strm;
	struct hlua *hlua = NULL;
	const char *error;

	if (!stream)
		return 0;

	if (!(hlua = hlua_stream_ctx_prepare(stream, fcn_ref_to_stack_id(fcn)))) {
		SEND_ERR(stream->be, "Lua converter '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua)) {
			hlua_lock(hlua);
			if (lua_type(hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(stream->be, "Lua converter '%s': %s.\n", fcn->name, error);
			hlua_unlock(hlua);
			return 0;
		}

		/* Check stack available size. */
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}

		/* Restore the function in the stack. */
		hlua_pushref(hlua->T, fcn->function_ref[hlua->state_id]);

		/* convert input sample and pust-it in the stack. */
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}
		MAY_LJMP(hlua_smp2lua(hlua->T, smp));
		hlua->nargs = 1;

		/* push keywords in the stack. */
		if (arg_p) {
			for (; arg_p->type != ARGT_STOP; arg_p++) {
				if (!lua_checkstack(hlua->T, 1)) {
					SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
					RESET_SAFE_LJMP(hlua);
					return 0;
				}
				MAY_LJMP(hlua_arg2lua(hlua->T, arg_p));
				hlua->nargs++;
			}
		}

		/* We must initialize the execution timeouts. */
		hlua_timer_init(&hlua->timer, hlua_timeout_session);

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		hlua_lock(hlua);
		/* If the stack is empty, the function fails. */
		if (lua_gettop(hlua->T) <= 0) {
			hlua_unlock(hlua);
			return 0;
		}

		/* Convert the returned value in sample. */
		hlua_lua2smp(hlua->T, -1, smp);
		/* dup the smp before popping the related lua value and
		 * returning it to haproxy
		 */
		smp_dup(smp);
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		SEND_ERR(stream->be, "Lua converter '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		hlua_lock(hlua);
		SEND_ERR(stream->be, "Lua converter '%s': %s.\n",
		         fcn->name, hlua_tostring_safe(hlua->T, -1));
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		return 0;

	case HLUA_E_ETMOUT:
		SEND_ERR(stream->be, "Lua converter '%s': execution timeout.\n", fcn->name);
		return 0;

	case HLUA_E_BTMOUT:
		SEND_ERR(stream->be, "Lua converter '%s': burst timeout.\n", fcn->name);
		return 0;

	case HLUA_E_NOMEM:
		SEND_ERR(stream->be, "Lua converter '%s': out of memory error.\n", fcn->name);
		return 0;

	case HLUA_E_YIELD:
		SEND_ERR(stream->be, "Lua converter '%s': yield functions like core.tcp() or core.sleep() are not allowed.\n", fcn->name);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		SEND_ERR(stream->be, "Lua converter '%s' returns an unknown error.\n", fcn->name);
		__fallthrough;

	default:
		return 0;
	}
}

/* Wrapper called by HAProxy to execute a sample-fetch. this wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume sample-fetches. This function will be called by the sample
 * fetch engine to call lua-based fetch operations.
 */
static int hlua_sample_fetch_wrapper(const struct arg *arg_p, struct sample *smp,
                                     const char *kw, void *private)
{
	struct hlua_function *fcn = private;
	struct stream *stream = smp->strm;
	struct hlua *hlua = NULL;
	const char *error;
	unsigned int hflags = HLUA_TXN_NOTERM | HLUA_TXN_SMP_CTX;

	if (!stream)
		return 0;

	if (!(hlua = hlua_stream_ctx_prepare(stream, fcn_ref_to_stack_id(fcn)))) {
		SEND_ERR(stream->be, "Lua sample-fetch '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua)) {
			hlua_lock(hlua);
			if (lua_type(hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(smp->px, "Lua sample-fetch '%s': %s.\n", fcn->name, error);
			hlua_unlock(hlua);
			return 0;
		}

		/* Check stack available size. */
		if (!lua_checkstack(hlua->T, 2)) {
			SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}

		/* Restore the function in the stack. */
		hlua_pushref(hlua->T, fcn->function_ref[hlua->state_id]);

		/* push arguments in the stack. */
		if (!hlua_txn_new(hlua->T, stream, smp->px, smp->opt & SMP_OPT_DIR, hflags)) {
			SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}
		hlua->nargs = 1;

		/* push keywords in the stack. */
		for (; arg_p && arg_p->type != ARGT_STOP; arg_p++) {
			/* Check stack available size. */
			if (!lua_checkstack(hlua->T, 1)) {
				SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
				RESET_SAFE_LJMP(hlua);
				return 0;
			}
			MAY_LJMP(hlua_arg2lua(hlua->T, arg_p));
			hlua->nargs++;
		}

		/* We must initialize the execution timeouts. */
		hlua_timer_init(&hlua->timer, hlua_timeout_session);

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		hlua_lock(hlua);
		/* If the stack is empty, the function fails. */
		if (lua_gettop(hlua->T) <= 0) {
			hlua_unlock(hlua);
			return 0;
		}

		/* Convert the returned value in sample. */
		hlua_lua2smp(hlua->T, -1, smp);
		/* dup the smp before popping the related lua value and
		 * returning it to haproxy
		 */
		smp_dup(smp);
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);

		/* Set the end of execution flag. */
		smp->flags &= ~SMP_F_MAY_CHANGE;
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		hlua_lock(hlua);
		SEND_ERR(smp->px, "Lua sample-fetch '%s': %s.\n",
		         fcn->name, hlua_tostring_safe(hlua->T, -1));
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		return 0;

	case HLUA_E_ETMOUT:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': execution timeout.\n", fcn->name);
		return 0;

	case HLUA_E_BTMOUT:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': burst timeout.\n", fcn->name);
		return 0;

	case HLUA_E_NOMEM:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': out of memory error.\n", fcn->name);
		return 0;

	case HLUA_E_YIELD:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': yield not allowed.\n", fcn->name);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		SEND_ERR(smp->px, "Lua sample-fetch '%s' returns an unknown error.\n", fcn->name);
		__fallthrough;

	default:
		return 0;
	}
}

/* This function is an LUA binding used for registering
 * "sample-conv" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_converters(lua_State *L)
{
	struct sample_conv_kw_list *sck;
	const char *name;
	int ref;
	int len;
	struct hlua_function *fcn = NULL;
	struct sample_conv *sc;
	struct buffer *trash;

	MAY_LJMP(check_args(L, 2, "register_converters"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_converters: not available outside of body context"));
	}

	/* First argument : converter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Check if the converter is already registered */
	trash = get_trash_chunk();
	chunk_printf(trash, "lua.%s", name);
	sc = find_sample_conv(trash->area, trash->data);
	if (sc != NULL) {
		fcn = sc->private;
		if (fcn->function_ref[hlua_state_id] != -1) {
			ha_warning("Trying to register converter 'lua.%s' more than once. "
			           "This will become a hard error in version 2.5.\n", name);
			hlua_unref(L, fcn->function_ref[hlua_state_id]);
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	sck = calloc(1, sizeof(*sck) + sizeof(struct sample_conv) * 2);
	if (!sck)
		goto alloc_error;
	fcn = new_hlua_function();
	if (!fcn)
		goto alloc_error;

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		goto alloc_error;
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	sck->list.n = sck->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sck->kw[0].kw = calloc(1, len);
	if (!sck->kw[0].kw)
		goto alloc_error;

	snprintf((char *)sck->kw[0].kw, len, "lua.%s", name);
	sck->kw[0].process = hlua_sample_conv_wrapper;
	sck->kw[0].arg_mask = ARG12(0,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR);
	sck->kw[0].val_args = NULL;
	sck->kw[0].in_type = SMP_T_STR;
	sck->kw[0].out_type = SMP_T_STR;
	sck->kw[0].private = fcn;

	/* Register this new converter */
	sample_register_convs(sck);

	return 0;

  alloc_error:
	release_hlua_function(fcn);
	hlua_unref(L, ref);
	ha_free(&sck);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

/* This function is an LUA binding used for registering
 * "sample-fetch" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_fetches(lua_State *L)
{
	const char *name;
	int ref;
	int len;
	struct sample_fetch_kw_list *sfk;
	struct hlua_function *fcn = NULL;
	struct sample_fetch *sf;
	struct buffer *trash;

	MAY_LJMP(check_args(L, 2, "register_fetches"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_fetches: not available outside of body context"));
	}

	/* First argument : sample-fetch name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Check if the sample-fetch is already registered */
	trash = get_trash_chunk();
	chunk_printf(trash, "lua.%s", name);
	sf = find_sample_fetch(trash->area, trash->data);
	if (sf != NULL) {
		fcn = sf->private;
		if (fcn->function_ref[hlua_state_id] != -1) {
			ha_warning("Trying to register sample-fetch 'lua.%s' more than once. "
			           "This will become a hard error in version 2.5.\n", name);
			hlua_unref(L, fcn->function_ref[hlua_state_id]);
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	sfk = calloc(1, sizeof(*sfk) + sizeof(struct sample_fetch) * 2);
	if (!sfk)
		goto alloc_error;
	fcn = new_hlua_function();
	if (!fcn)
		goto alloc_error;

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		goto alloc_error;
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	sfk->list.n = sfk->list.p = NULL;

	/* sample-fetch keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sfk->kw[0].kw = calloc(1, len);
	if (!sfk->kw[0].kw)
		goto alloc_error;

	snprintf((char *)sfk->kw[0].kw, len, "lua.%s", name);
	sfk->kw[0].process = hlua_sample_fetch_wrapper;
	sfk->kw[0].arg_mask = ARG12(0,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR);
	sfk->kw[0].val_args = NULL;
	sfk->kw[0].out_type = SMP_T_STR;
	sfk->kw[0].use = SMP_USE_HTTP_ANY;
	sfk->kw[0].val = 0;
	sfk->kw[0].private = fcn;

	/* Register this new fetch. */
	sample_register_fetches(sfk);

	return 0;

  alloc_error:
	release_hlua_function(fcn);
	hlua_unref(L, ref);
	ha_free(&sfk);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

/* This function is a lua binding to set the wake_time.
 */
__LJMP static int hlua_set_wake_time(lua_State *L)
{
	struct hlua *hlua;
	unsigned int delay;
	int wakeup_ms; // tick value

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		return 0;
	}

	MAY_LJMP(check_args(L, 1, "wake_time"));

	delay = MAY_LJMP(luaL_checkinteger(L, 1));
	wakeup_ms = tick_add(now_ms, delay);
	hlua->wake_time = wakeup_ms;
	return 0;
}

/* This function is a wrapper to execute each LUA function declared as an action
 * wrapper during the initialisation period. This function may return any
 * ACT_RET_* value. On error ACT_RET_CONT is returned and the action is
 * ignored. If the lua action yields, ACT_RET_YIELD is returned. On success, the
 * return value is the first element on the stack.
 */
static enum act_return hlua_action(struct act_rule *rule, struct proxy *px,
                                   struct session *sess, struct stream *s, int flags)
{
	char **arg;
	unsigned int hflags = HLUA_TXN_ACT_CTX;
	int dir, act_ret = ACT_RET_CONT;
	const char *error;
	struct hlua *hlua = NULL;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CNT: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_RES_CNT: dir = SMP_OPT_DIR_RES; break;
	case ACT_F_HTTP_REQ:    dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_HTTP_RES:    dir = SMP_OPT_DIR_RES; break;
	default:
		SEND_ERR(px, "Lua: internal error while execute action.\n");
		goto end;
	}

	if (!(hlua = hlua_stream_ctx_prepare(s, fcn_ref_to_stack_id(rule->arg.hlua_rule->fcn)))) {
		SEND_ERR(px, "Lua action '%s': can't initialize Lua context.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto end;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua)) {
			hlua_lock(hlua);
			if (lua_type(hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(px, "Lua function '%s': %s.\n",
			         rule->arg.hlua_rule->fcn->name, error);
			hlua_unlock(hlua);
			goto end;
		}

		/* Check stack available size. */
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(px, "Lua function '%s': full stack.\n",
			         rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			goto end;
		}

		/* Restore the function in the stack. */
		hlua_pushref(hlua->T, rule->arg.hlua_rule->fcn->function_ref[hlua->state_id]);

		/* Create and and push object stream in the stack. */
		if (!hlua_txn_new(hlua->T, s, px, dir, hflags)) {
			SEND_ERR(px, "Lua function '%s': full stack.\n",
			         rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			goto end;
		}
		hlua->nargs = 1;

		/* push keywords in the stack. */
		for (arg = rule->arg.hlua_rule->args; arg && *arg; arg++) {
			if (!lua_checkstack(hlua->T, 1)) {
				SEND_ERR(px, "Lua function '%s': full stack.\n",
				         rule->arg.hlua_rule->fcn->name);
				RESET_SAFE_LJMP(hlua);
				goto end;
			}
			lua_pushstring(hlua->T, *arg);
			hlua->nargs++;
		}

		/* Now the execution is safe. */
		RESET_SAFE_LJMP(hlua);

		/* We must initialize the execution timeouts. */
		hlua_timer_init(&hlua->timer, hlua_timeout_session);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, !(flags & ACT_OPT_FINAL))) {
	/* finished. */
	case HLUA_E_OK:
		/* Catch the return value */
		hlua_lock(hlua);
		if (lua_gettop(hlua->T) > 0)
			act_ret = lua_tointeger(hlua->T, -1);
		hlua_unlock(hlua);

		/* Set timeout in the required channel. */
		if (act_ret == ACT_RET_YIELD) {
			if (flags & ACT_OPT_FINAL)
				goto err_yield;

			if (dir == SMP_OPT_DIR_REQ)
				s->req.analyse_exp = tick_first((tick_is_expired(s->req.analyse_exp, now_ms) ? 0 : s->req.analyse_exp),
								hlua->wake_time);
			else
				s->res.analyse_exp = tick_first((tick_is_expired(s->res.analyse_exp, now_ms) ? 0 : s->res.analyse_exp),
								hlua->wake_time);
		}
		goto end;

	/* yield. */
	case HLUA_E_AGAIN:
		/* Set timeout in the required channel. */
		if (dir == SMP_OPT_DIR_REQ)
			s->req.analyse_exp = tick_first((tick_is_expired(s->req.analyse_exp, now_ms) ? 0 : s->req.analyse_exp),
							hlua->wake_time);
		else
			s->res.analyse_exp = tick_first((tick_is_expired(s->res.analyse_exp, now_ms) ? 0 : s->res.analyse_exp),
							hlua->wake_time);

		/* Some actions can be wake up when a "write" event
		 * is detected on a response channel. This is useful
		 * only for actions targeted on the requests.
		 */
		if (HLUA_IS_WAKERESWR(hlua))
			s->res.flags |= CF_WAKE_WRITE;
		if (HLUA_IS_WAKEREQWR(hlua))
			s->req.flags |= CF_WAKE_WRITE;
		act_ret = ACT_RET_YIELD;
		goto end;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		hlua_lock(hlua);
		SEND_ERR(px, "Lua function '%s': %s.\n",
		         rule->arg.hlua_rule->fcn->name, hlua_tostring_safe(hlua->T, -1));
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		goto end;

	case HLUA_E_ETMOUT:
		SEND_ERR(px, "Lua function '%s': execution timeout.\n", rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_BTMOUT:
		SEND_ERR(px, "Lua function '%s': burst timeout.\n", rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_NOMEM:
		SEND_ERR(px, "Lua function '%s': out of memory error.\n", rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_YIELD:
	  err_yield:
		act_ret = ACT_RET_CONT;
		SEND_ERR(px, "Lua function '%s': yield not allowed.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_ERR:
		/* Display log. */
		SEND_ERR(px, "Lua function '%s' return an unknown error.\n",
		         rule->arg.hlua_rule->fcn->name);

	default:
		goto end;
	}

 end:
	if (act_ret != ACT_RET_YIELD && hlua)
		hlua->wake_time = TICK_ETERNITY;
	return act_ret;
}

struct task *hlua_applet_wakeup(struct task *t, void *context, unsigned int state)
{
	struct appctx *ctx = context;

	appctx_wakeup(ctx);
	t->expire = TICK_ETERNITY;
	return t;
}

static int hlua_applet_tcp_init(struct appctx *ctx)
{
	struct hlua_tcp_ctx *tcp_ctx = applet_reserve_svcctx(ctx, sizeof(*tcp_ctx));
	struct stconn *sc = appctx_sc(ctx);
	struct stream *strm = __sc_strm(sc);
	struct hlua *hlua;
	struct task *task;
	char **arg;
	const char *error;

	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(strm->be, "Lua applet tcp '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}
	HLUA_INIT(hlua);
	tcp_ctx->hlua = hlua;
	tcp_ctx->flags = 0;

	/* Create task used by signal to wakeup applets. */
	task = task_new_here();
	if (!task) {
		SEND_ERR(strm->be, "Lua applet tcp '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}
	task->nice = 0;
	task->context = ctx;
	task->process = hlua_applet_wakeup;
	tcp_ctx->task = task;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(ctx->rule->arg.hlua_rule->fcn), task)) {
		SEND_ERR(strm->be, "Lua applet tcp '%s': can't initialize Lua context.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}

	/* Set timeout according with the applet configuration. */
	hlua_timer_init(&hlua->timer, ctx->applet->timeout);

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		hlua_lock(hlua);
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = hlua_tostring_safe(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(strm->be, "Lua applet tcp '%s': %s.\n",
		         ctx->rule->arg.hlua_rule->fcn->name, error);
		hlua_unlock(hlua);
		return -1;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 1)) {
		SEND_ERR(strm->be, "Lua applet tcp '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return -1;
	}

	/* Restore the function in the stack. */
	hlua_pushref(hlua->T, ctx->rule->arg.hlua_rule->fcn->function_ref[hlua->state_id]);

	/* Create and and push object stream in the stack. */
	if (!hlua_applet_tcp_new(hlua->T, ctx)) {
		SEND_ERR(strm->be, "Lua applet tcp '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return -1;
	}
	hlua->nargs = 1;

	/* push keywords in the stack. */
	for (arg = ctx->rule->arg.hlua_rule->args; arg && *arg; arg++) {
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(strm->be, "Lua applet tcp '%s': full stack.\n",
			         ctx->rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			return -1;
		}
		lua_pushstring(hlua->T, *arg);
		hlua->nargs++;
	}

	RESET_SAFE_LJMP(hlua);

	/* Wakeup the applet ASAP. */
	applet_need_more_data(ctx);
	applet_have_more_data(ctx);

	return 0;
}

void hlua_applet_tcp_fct(struct appctx *ctx)
{
	struct hlua_tcp_ctx *tcp_ctx = ctx->svcctx;
	struct stconn *sc = appctx_sc(ctx);
	struct stream *strm = __sc_strm(sc);
	struct act_rule *rule = ctx->rule;
	struct proxy *px = strm->be;
	struct hlua *hlua = tcp_ctx->hlua;

	if (unlikely(se_fl_test(ctx->sedesc, (SE_FL_EOS|SE_FL_ERROR|SE_FL_SHR|SE_FL_SHW))))
		goto out;

	/* The applet execution is already done. */
	if (tcp_ctx->flags & APPLET_DONE)
		goto out;

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 1)) {
	/* finished. */
	case HLUA_E_OK:
		tcp_ctx->flags |= APPLET_DONE;
		se_fl_set(ctx->sedesc, SE_FL_EOI|SE_FL_EOS);
		break;

	/* yield. */
	case HLUA_E_AGAIN:
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(tcp_ctx->task, hlua->wake_time);
		break;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		hlua_lock(hlua);
		SEND_ERR(px, "Lua applet tcp '%s': %s.\n",
		         rule->arg.hlua_rule->fcn->name, hlua_tostring_safe(hlua->T, -1));
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		goto error;

	case HLUA_E_ETMOUT:
		SEND_ERR(px, "Lua applet tcp '%s': execution timeout.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto error;

	case HLUA_E_BTMOUT:
		SEND_ERR(px, "Lua applet tcp '%s': burst timeout.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto error;

	case HLUA_E_NOMEM:
		SEND_ERR(px, "Lua applet tcp '%s': out of memory error.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto error;

	case HLUA_E_YIELD: /* unexpected */
		SEND_ERR(px, "Lua applet tcp '%s': yield not allowed.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto error;

	case HLUA_E_ERR:
		/* Display log. */
		SEND_ERR(px, "Lua applet tcp '%s' return an unknown error.\n",
		         rule->arg.hlua_rule->fcn->name);
		goto error;

	default:
		goto error;
	}

out:
	/* eat the whole request */
	if (ctx->flags & APPCTX_FL_INOUT_BUFS)
		b_reset(&ctx->inbuf);
	else
		co_skip(sc_oc(sc), co_data(sc_oc(sc)));
	return;

error:
	se_fl_set(ctx->sedesc, SE_FL_ERROR);
	tcp_ctx->flags |= APPLET_DONE;
	goto out;
}

static void hlua_applet_tcp_release(struct appctx *ctx)
{
	struct hlua_tcp_ctx *tcp_ctx = ctx->svcctx;

	task_destroy(tcp_ctx->task);
	tcp_ctx->task = NULL;
	hlua_ctx_destroy(tcp_ctx->hlua);
	tcp_ctx->hlua = NULL;
}

/* The function returns 0 if the initialisation is complete or -1 if
 * an errors occurs. It also reserves the appctx for an hlua_http_ctx.
 */
static int hlua_applet_http_init(struct appctx *ctx)
{
	struct hlua_http_ctx *http_ctx = applet_reserve_svcctx(ctx, sizeof(*http_ctx));
	struct stconn *sc = appctx_sc(ctx);
	struct stream *strm = __sc_strm(sc);
	struct http_txn *txn;
	struct hlua *hlua;
	char **arg;
	struct task *task;
	const char *error;

	txn = strm->txn;
	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(strm->be, "Lua applet http '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}
	HLUA_INIT(hlua);
	http_ctx->hlua = hlua;
	http_ctx->left_bytes = -1;
	http_ctx->flags = 0;

	if (txn->req.flags & HTTP_MSGF_VER_11)
		http_ctx->flags |= APPLET_HTTP11;

	/* Create task used by signal to wakeup applets. */
	task = task_new_here();
	if (!task) {
		SEND_ERR(strm->be, "Lua applet http '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}
	task->nice = 0;
	task->context = ctx;
	task->process = hlua_applet_wakeup;
	http_ctx->task = task;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(ctx->rule->arg.hlua_rule->fcn), task)) {
		SEND_ERR(strm->be, "Lua applet http '%s': can't initialize Lua context.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return -1;
	}

	/* Set timeout according with the applet configuration. */
	hlua_timer_init(&hlua->timer, ctx->applet->timeout);

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		hlua_lock(hlua);
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = hlua_tostring_safe(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(strm->be, "Lua applet http '%s': %s.\n",
		         ctx->rule->arg.hlua_rule->fcn->name, error);
		hlua_unlock(hlua);
		return -1;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 1)) {
		SEND_ERR(strm->be, "Lua applet http '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return -1;
	}

	/* Restore the function in the stack. */
	hlua_pushref(hlua->T, ctx->rule->arg.hlua_rule->fcn->function_ref[hlua->state_id]);

	/* Create and and push object stream in the stack. */
	if (!hlua_applet_http_new(hlua->T, ctx)) {
		SEND_ERR(strm->be, "Lua applet http '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return -1;
	}
	hlua->nargs = 1;

	/* push keywords in the stack. */
	for (arg = ctx->rule->arg.hlua_rule->args; arg && *arg; arg++) {
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(strm->be, "Lua applet http '%s': full stack.\n",
			         ctx->rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			return -1;
		}
		lua_pushstring(hlua->T, *arg);
		hlua->nargs++;
	}

	RESET_SAFE_LJMP(hlua);

	/* Wakeup the applet when data is ready for read. */
	applet_need_more_data(ctx);

	return 0;
}

void hlua_applet_http_fct(struct appctx *ctx)
{
	struct hlua_http_ctx *http_ctx = ctx->svcctx;
	struct stconn *sc = appctx_sc(ctx);
	struct stream *strm = __sc_strm(sc);
	struct channel *req = sc_oc(sc);
	struct channel *res = sc_ic(sc);
	struct act_rule *rule = ctx->rule;
	struct proxy *px = strm->be;
	struct hlua *hlua = http_ctx->hlua;
	struct htx *req_htx, *res_htx;

	res_htx = htx_from_buf(&res->buf);

	if (unlikely(se_fl_test(ctx->sedesc, (SE_FL_EOS|SE_FL_ERROR|SE_FL_SHR|SE_FL_SHW))))
		goto out;

	/* The applet execution is already done. */
	if (http_ctx->flags & APPLET_DONE)
		goto out;

	/* Check if the input buffer is available. */
	if (!b_size(&res->buf)) {
		sc_need_room(sc, 0);
		goto out;
	}

	/* Set the currently running flag. */
	if (!HLUA_IS_RUNNING(hlua) &&
	    !(http_ctx->flags & APPLET_DONE)) {
		if (!co_data(req)) {
			applet_need_more_data(ctx);
			goto out;
		}
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 1)) {
		/* finished. */
		case HLUA_E_OK:
			http_ctx->flags |= APPLET_DONE;
			break;

		/* yield. */
		case HLUA_E_AGAIN:
			if (hlua->wake_time != TICK_ETERNITY)
				task_schedule(http_ctx->task, hlua->wake_time);
			goto out;

		/* finished with error. */
		case HLUA_E_ERRMSG:
			/* Display log. */
			hlua_lock(hlua);
			SEND_ERR(px, "Lua applet http '%s': %s.\n",
				 rule->arg.hlua_rule->fcn->name, hlua_tostring_safe(hlua->T, -1));
			lua_pop(hlua->T, 1);
			hlua_unlock(hlua);
			goto error;

		case HLUA_E_ETMOUT:
			SEND_ERR(px, "Lua applet http '%s': execution timeout.\n",
				 rule->arg.hlua_rule->fcn->name);
			goto error;

		case HLUA_E_BTMOUT:
			SEND_ERR(px, "Lua applet http '%s': burst timeout.\n",
				 rule->arg.hlua_rule->fcn->name);
			goto error;

		case HLUA_E_NOMEM:
			SEND_ERR(px, "Lua applet http '%s': out of memory error.\n",
				 rule->arg.hlua_rule->fcn->name);
			goto error;

		case HLUA_E_YIELD: /* unexpected */
			SEND_ERR(px, "Lua applet http '%s': yield not allowed.\n",
				 rule->arg.hlua_rule->fcn->name);
			goto error;

		case HLUA_E_ERR:
			/* Display log. */
			SEND_ERR(px, "Lua applet http '%s' return an unknown error.\n",
				 rule->arg.hlua_rule->fcn->name);
			goto error;

		default:
			goto error;
	}

	if (http_ctx->flags & APPLET_DONE) {
		if (http_ctx->flags & APPLET_RSP_SENT)
			goto out;

		if (!(http_ctx->flags & APPLET_HDR_SENT))
			goto error;

		/* no more data are expected. If the response buffer is empty
		 * for a chunked message, be sure to add something (EOT block in
		 * this case) to have something to send. It is important to be
		 * sure the EOM flags will be handled by the endpoint.
		 */
		if (htx_is_empty(res_htx) && (strm->txn->rsp.flags & (HTTP_MSGF_XFER_LEN|HTTP_MSGF_CNT_LEN)) == HTTP_MSGF_XFER_LEN) {
			if (!htx_add_endof(res_htx, HTX_BLK_EOT)) {
				sc_need_room(sc, sizeof(struct htx_blk)+1);
				goto out;
			}
			channel_add_input(res, 1);
		}

		res_htx->flags |= HTX_FL_EOM;
		se_fl_set(ctx->sedesc, SE_FL_EOI|SE_FL_EOS);
		strm->txn->status = http_ctx->status;
		http_ctx->flags |= APPLET_RSP_SENT;
	}

  out:
	htx_to_buf(res_htx, &res->buf);
	/* eat the whole request */
	if (co_data(req)) {
		req_htx = htx_from_buf(&req->buf);
		co_htx_skip(req, req_htx, co_data(req));
		htx_to_buf(req_htx, &req->buf);
	}
	return;

  error:

	/* If we are in HTTP mode, and we are not send any
	 * data, return a 500 server error in best effort:
	 * if there is no room available in the buffer,
	 * just close the connection.
	 */
	if (!(http_ctx->flags & APPLET_HDR_SENT)) {
		struct buffer *err = &http_err_chunks[HTTP_ERR_500];

		channel_erase(res);
		res->buf.data = b_data(err);
                memcpy(res->buf.area, b_head(err), b_data(err));
                res_htx = htx_from_buf(&res->buf);
		channel_add_input(res, res_htx->data);
		se_fl_set(ctx->sedesc, SE_FL_EOI|SE_FL_EOS);
	}
	else
		se_fl_set(ctx->sedesc, SE_FL_ERROR);

	if (!(strm->flags & SF_ERR_MASK))
		strm->flags |= SF_ERR_RESOURCE;
	http_ctx->flags |= APPLET_DONE;
	goto out;
}

static void hlua_applet_http_release(struct appctx *ctx)
{
	struct hlua_http_ctx *http_ctx = ctx->svcctx;

	task_destroy(http_ctx->task);
	http_ctx->task = NULL;
	hlua_ctx_destroy(http_ctx->hlua);
	http_ctx->hlua = NULL;
}

/* global {tcp|http}-request parser. Return ACT_RET_PRS_OK in
 * success case, else return ACT_RET_PRS_ERR.
 *
 * This function can fail with an abort() due to an Lua critical error.
 * We are in the configuration parsing process of HAProxy, this abort() is
 * tolerated.
 */
static enum act_parse_ret action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                              struct act_rule *rule, char **err)
{
	struct hlua_function *fcn = rule->kw->private;
	int i;

	/* Memory for the rule. */
	rule->arg.hlua_rule = calloc(1, sizeof(*rule->arg.hlua_rule));
	if (!rule->arg.hlua_rule) {
		memprintf(err, "out of memory error");
		goto error;
	}

	/* Memory for arguments. */
	rule->arg.hlua_rule->args = calloc(fcn->nargs + 1,
					   sizeof(*rule->arg.hlua_rule->args));
	if (!rule->arg.hlua_rule->args) {
		memprintf(err, "out of memory error");
		goto error;
	}

	/* Reference the Lua function and store the reference. */
	rule->arg.hlua_rule->fcn = fcn;

	/* Expect some arguments */
	for (i = 0; i < fcn->nargs; i++) {
		if (*args[*cur_arg] == '\0') {
			memprintf(err, "expect %d arguments", fcn->nargs);
			goto error;
		}
		rule->arg.hlua_rule->args[i] = strdup(args[*cur_arg]);
		if (!rule->arg.hlua_rule->args[i]) {
			memprintf(err, "out of memory error");
			goto error;
		}
		(*cur_arg)++;
	}
	rule->arg.hlua_rule->args[i] = NULL;

	rule->action = ACT_CUSTOM;
	rule->action_ptr = hlua_action;
	return ACT_RET_PRS_OK;

  error:
	if (rule->arg.hlua_rule) {
		if (rule->arg.hlua_rule->args) {
			for (i = 0; i < fcn->nargs; i++)
				ha_free(&rule->arg.hlua_rule->args[i]);
			ha_free(&rule->arg.hlua_rule->args);
		}
		ha_free(&rule->arg.hlua_rule);
	}
	return ACT_RET_PRS_ERR;
}

static enum act_parse_ret action_register_service_http(const char **args, int *cur_arg, struct proxy *px,
                                                       struct act_rule *rule, char **err)
{
	struct hlua_function *fcn = rule->kw->private;

	/* HTTP applets are forbidden in tcp-request rules.
	 * HTTP applet request requires everything initialized by
	 * "http_process_request" (analyzer flag AN_REQ_HTTP_INNER).
	 * The applet will be immediately initialized, but its before
	 * the call of this analyzer.
	 */
	if (rule->from != ACT_F_HTTP_REQ) {
		memprintf(err, "HTTP applets are forbidden from 'tcp-request' rulesets");
		return ACT_RET_PRS_ERR;
	}

	/* Memory for the rule. */
	rule->arg.hlua_rule = calloc(1, sizeof(*rule->arg.hlua_rule));
	if (!rule->arg.hlua_rule) {
		memprintf(err, "out of memory error");
		return ACT_RET_PRS_ERR;
	}

	/* Reference the Lua function and store the reference. */
	rule->arg.hlua_rule->fcn = fcn;

	/* TODO: later accept arguments. */
	rule->arg.hlua_rule->args = NULL;

	/* Add applet pointer in the rule. */
	rule->applet.obj_type = OBJ_TYPE_APPLET;
	rule->applet.name = fcn->name;
	rule->applet.init = hlua_applet_http_init;
	rule->applet.fct = hlua_applet_http_fct;
	rule->applet.release = hlua_applet_http_release;
	rule->applet.timeout = hlua_timeout_applet;

	return ACT_RET_PRS_OK;
}

/* This function is an LUA binding used for registering
 * "sample-conv" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_action(lua_State *L)
{
	struct action_kw_list *akl = NULL;
	const char *name;
	int ref;
	int len;
	struct hlua_function *fcn = NULL;
	int nargs;
	struct buffer *trash;
	struct action_kw *akw;

	/* Initialise the number of expected arguments at 0. */
	nargs = 0;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'register_action' needs between 3 and 4 arguments"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_action: not available outside of body context"));
	}

	/* First argument : converter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : environment. */
	if (lua_type(L, 2) != LUA_TTABLE)
		WILL_LJMP(luaL_error(L, "register_action: second argument must be a table of strings"));

	/* Third argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 3));

	/* Fourth argument : number of mandatory arguments expected on the configuration line. */
	if (lua_gettop(L) >= 4)
		nargs = MAY_LJMP(luaL_checkinteger(L, 4));

	/* browse the second argument as an array. */
	lua_pushnil(L);
	while (lua_next(L, 2) != 0) {
		if (lua_type(L, -1) != LUA_TSTRING) {
			hlua_unref(L, ref);
			WILL_LJMP(luaL_error(L, "register_action: second argument must be a table of strings"));
		}

		/* Check if action exists */
		trash = get_trash_chunk();
		chunk_printf(trash, "lua.%s", name);
		if (strcmp(lua_tostring(L, -1), "tcp-req") == 0) {
			akw = tcp_req_cont_action(trash->area);
		} else if (strcmp(lua_tostring(L, -1), "tcp-res") == 0) {
			akw = tcp_res_cont_action(trash->area);
		} else if (strcmp(lua_tostring(L, -1), "http-req") == 0) {
			akw = action_http_req_custom(trash->area);
		} else if (strcmp(lua_tostring(L, -1), "http-res") == 0) {
			akw = action_http_res_custom(trash->area);
		} else if (strcmp(lua_tostring(L, -1), "http-after-res") == 0) {
			akw = action_http_after_res_custom(trash->area);
		} else {
			akw = NULL;
		}
		if (akw != NULL) {
			fcn = akw->private;
			if (fcn->function_ref[hlua_state_id] != -1) {
				ha_warning("Trying to register action 'lua.%s' more than once. "
				           "This will become a hard error in version 2.5.\n", name);
				hlua_unref(L, fcn->function_ref[hlua_state_id]);
			}
			fcn->function_ref[hlua_state_id] = ref;

			/* pop the environment string. */
			lua_pop(L, 1);
			continue;
		}

		/* Check required environment. Only accepted "http" or "tcp". */
		/* Allocate and fill the sample fetch keyword struct. */
		akl = calloc(1, sizeof(*akl) + sizeof(struct action_kw) * 2);
		if (!akl)
			goto alloc_error;;
		fcn = new_hlua_function();
		if (!fcn)
			goto alloc_error;

		/* Fill fcn. */
		fcn->name = strdup(name);
		if (!fcn->name)
			goto alloc_error;
		fcn->function_ref[hlua_state_id] = ref;

		/* Set the expected number of arguments. */
		fcn->nargs = nargs;

		/* List head */
		akl->list.n = akl->list.p = NULL;

		/* action keyword. */
		len = strlen("lua.") + strlen(name) + 1;
		akl->kw[0].kw = calloc(1, len);
		if (!akl->kw[0].kw)
			goto alloc_error;

		snprintf((char *)akl->kw[0].kw, len, "lua.%s", name);

		akl->kw[0].flags = 0;
		akl->kw[0].private = fcn;
		akl->kw[0].parse = action_register_lua;

		/* select the action registering point. */
		if (strcmp(lua_tostring(L, -1), "tcp-req") == 0)
			tcp_req_cont_keywords_register(akl);
		else if (strcmp(lua_tostring(L, -1), "tcp-res") == 0)
			tcp_res_cont_keywords_register(akl);
		else if (strcmp(lua_tostring(L, -1), "http-req") == 0)
			http_req_keywords_register(akl);
		else if (strcmp(lua_tostring(L, -1), "http-res") == 0)
			http_res_keywords_register(akl);
		else if (strcmp(lua_tostring(L, -1), "http-after-res") == 0)
			http_after_res_keywords_register(akl);
		else {
			release_hlua_function(fcn);
			hlua_unref(L, ref);
			if (akl)
				ha_free((char **)&(akl->kw[0].kw));
			ha_free(&akl);
			WILL_LJMP(luaL_error(L, "Lua action environment '%s' is unknown. "
			                        "'tcp-req', 'tcp-res', 'http-req', 'http-res' "
			                        "or 'http-after-res' "
			                        "are expected.", lua_tostring(L, -1)));
		}

		/* pop the environment string. */
		lua_pop(L, 1);

		/* reset for next loop */
		akl = NULL;
		fcn = NULL;
	}
	return ACT_RET_PRS_OK;

  alloc_error:
	release_hlua_function(fcn);
	hlua_unref(L, ref);
	ha_free(&akl);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

static enum act_parse_ret action_register_service_tcp(const char **args, int *cur_arg, struct proxy *px,
                                                      struct act_rule *rule, char **err)
{
	struct hlua_function *fcn = rule->kw->private;

	if (px->mode == PR_MODE_HTTP) {
		memprintf(err, "Lua TCP services cannot be used on HTTP proxies");
		return ACT_RET_PRS_ERR;
	}

	/* Memory for the rule. */
	rule->arg.hlua_rule = calloc(1, sizeof(*rule->arg.hlua_rule));
	if (!rule->arg.hlua_rule) {
		memprintf(err, "out of memory error");
		return ACT_RET_PRS_ERR;
	}

	/* Reference the Lua function and store the reference. */
	rule->arg.hlua_rule->fcn = fcn;

	/* TODO: later accept arguments. */
	rule->arg.hlua_rule->args = NULL;

	/* Add applet pointer in the rule. */
	rule->applet.obj_type = OBJ_TYPE_APPLET;
	rule->applet.name = fcn->name;
	rule->applet.init = hlua_applet_tcp_init;
	rule->applet.fct = hlua_applet_tcp_fct;
	rule->applet.release = hlua_applet_tcp_release;
	rule->applet.timeout = hlua_timeout_applet;

	return 0;
}

/* This function is an LUA binding used for registering
 * "sample-conv" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_service(lua_State *L)
{
	struct action_kw_list *akl;
	const char *name;
	const char *env;
	int ref;
	int len;
	struct hlua_function *fcn = NULL;
	struct buffer *trash;
	struct action_kw *akw;

	MAY_LJMP(check_args(L, 3, "register_service"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_service: not available outside of body context"));
	}

	/* First argument : converter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : environment. */
	env = MAY_LJMP(luaL_checkstring(L, 2));

	/* Third argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 3));

	/* Check for service already registered */
	trash = get_trash_chunk();
	chunk_printf(trash, "lua.%s", name);
	akw = service_find(trash->area);
	if (akw != NULL) {
		fcn = akw->private;
		if (fcn->function_ref[hlua_state_id] != -1) {
			ha_warning("Trying to register service 'lua.%s' more than once. "
			           "This will become a hard error in version 2.5.\n", name);
			hlua_unref(L, fcn->function_ref[hlua_state_id]);
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	akl = calloc(1, sizeof(*akl) + sizeof(struct action_kw) * 2);
	if (!akl)
		goto alloc_error;
	fcn = new_hlua_function();
	if (!fcn)
		goto alloc_error;

	/* Fill fcn. */
	len = strlen("<lua.>") + strlen(name) + 1;
	fcn->name = calloc(1, len);
	if (!fcn->name)
		goto alloc_error;
	snprintf((char *)fcn->name, len, "<lua.%s>", name);
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	akl->list.n = akl->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	akl->kw[0].kw = calloc(1, len);
	if (!akl->kw[0].kw)
		goto alloc_error;

	snprintf((char *)akl->kw[0].kw, len, "lua.%s", name);

	/* Check required environment. Only accepted "http" or "tcp". */
	if (strcmp(env, "tcp") == 0)
		akl->kw[0].parse = action_register_service_tcp;
	else if (strcmp(env, "http") == 0)
		akl->kw[0].parse = action_register_service_http;
	else {
		release_hlua_function(fcn);
		hlua_unref(L, ref);
		if (akl)
			ha_free((char **)&(akl->kw[0].kw));
		ha_free(&akl);
		WILL_LJMP(luaL_error(L, "Lua service environment '%s' is unknown. "
		                        "'tcp' or 'http' are expected.", env));
	}

	akl->kw[0].flags = 0;
	akl->kw[0].private = fcn;

	/* End of array. */
	memset(&akl->kw[1], 0, sizeof(*akl->kw));

	/* Register this new converter */
	service_keywords_register(akl);

	return 0;

  alloc_error:
	release_hlua_function(fcn);
	hlua_unref(L, ref);
	ha_free(&akl);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

/* This function initialises Lua cli handler. It copies the
 * arguments in the Lua stack and create channel IO objects.
 */
static int hlua_cli_parse_fct(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct hlua_cli_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct hlua *hlua;
	struct hlua_function *fcn;
	int i;
	const char *error;

	fcn = private;
	ctx->fcn = private;

	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(NULL, "Lua cli '%s': out of memory.\n", fcn->name);
		return 1;
	}
	HLUA_INIT(hlua);
	ctx->hlua = hlua;

	/* Create task used by signal to wakeup applets.
	 * We use the same wakeup function than the Lua applet_tcp and
	 * applet_http. It is absolutely compatible.
	 */
	ctx->task = task_new_here();
	if (!ctx->task) {
		SEND_ERR(NULL, "Lua cli '%s': out of memory.\n", fcn->name);
		goto error;
	}
	ctx->task->nice = 0;
	ctx->task->context = appctx;
	ctx->task->process = hlua_applet_wakeup;

	/* Initialises the Lua context */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(fcn), ctx->task)) {
		SEND_ERR(NULL, "Lua cli '%s': can't initialize Lua context.\n", fcn->name);
		goto error;
	}

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		hlua_lock(hlua);
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = hlua_tostring_safe(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(NULL, "Lua cli '%s': %s.\n", fcn->name, error);
		hlua_unlock(hlua);
		goto error;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 2)) {
		SEND_ERR(NULL, "Lua cli '%s': full stack.\n", fcn->name);
		goto error;
	}

	/* Restore the function in the stack. */
	hlua_pushref(hlua->T, fcn->function_ref[hlua->state_id]);

	/* Once the arguments parsed, the CLI is like an AppletTCP,
	 * so push AppletTCP in the stack.
	 */
	if (!hlua_applet_tcp_new(hlua->T, appctx)) {
		SEND_ERR(NULL, "Lua cli '%s': full stack.\n", fcn->name);
		goto error;
	}
	hlua->nargs = 1;

	/* push keywords in the stack. */
	for (i = 0; *args[i]; i++) {
		/* Check stack available size. */
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(NULL, "Lua cli '%s': full stack.\n", fcn->name);
			goto error;
		}
		lua_pushstring(hlua->T, args[i]);
		hlua->nargs++;
	}

	/* We must initialize the execution timeouts. */
	hlua_timer_init(&hlua->timer, hlua_timeout_session);

	/* At this point the execution is safe. */
	RESET_SAFE_LJMP(hlua);

	/* It's ok */
	return 0;

	/* It's not ok. */
error:
	RESET_SAFE_LJMP(hlua);
	hlua_ctx_destroy(hlua);
	ctx->hlua = NULL;
	return 1;
}

static int hlua_cli_io_handler_fct(struct appctx *appctx)
{
	struct hlua_cli_ctx *ctx = appctx->svcctx;
	struct hlua *hlua;
	struct stconn *sc;
	struct hlua_function *fcn;

	hlua = ctx->hlua;
	sc = appctx_sc(appctx);
	fcn = ctx->fcn;

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 1)) {

	/* finished. */
	case HLUA_E_OK:
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		/* We want write. */
		if (HLUA_IS_WAKERESWR(hlua))
			sc_need_room(sc, -1);
		/* Set the timeout. */
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(hlua->task, hlua->wake_time);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		hlua_lock(hlua);
		SEND_ERR(NULL, "Lua cli '%s': %s.\n",
		         fcn->name, hlua_tostring_safe(hlua->T, -1));
		lua_pop(hlua->T, 1);
		hlua_unlock(hlua);
		return 1;

	case HLUA_E_ETMOUT:
		SEND_ERR(NULL, "Lua cli '%s': execution timeout.\n",
		         fcn->name);
		return 1;

	case HLUA_E_BTMOUT:
		SEND_ERR(NULL, "Lua cli '%s': burst timeout.\n",
		         fcn->name);
		return 1;

	case HLUA_E_NOMEM:
		SEND_ERR(NULL, "Lua cli '%s': out of memory error.\n",
		         fcn->name);
		return 1;

	case HLUA_E_YIELD: /* unexpected */
		SEND_ERR(NULL, "Lua cli '%s': yield not allowed.\n",
		         fcn->name);
		return 1;

	case HLUA_E_ERR:
		/* Display log. */
		SEND_ERR(NULL, "Lua cli '%s' return an unknown error.\n",
		         fcn->name);
		return 1;

	default:
		return 1;
	}

	return 1;
}

static void hlua_cli_io_release_fct(struct appctx *appctx)
{
	struct hlua_cli_ctx *ctx = appctx->svcctx;

	hlua_ctx_destroy(ctx->hlua);
	ctx->hlua = NULL;
}

/* This function is an LUA binding used for registering
 * new keywords in the cli. It expects a list of keywords
 * which are the "path". It is limited to 5 keywords. A
 * description of the command, a function to be executed
 * for the parsing and a function for io handlers.
 */
__LJMP static int hlua_register_cli(lua_State *L)
{
	struct cli_kw_list *cli_kws;
	const char *message;
	int ref_io;
	int len;
	struct hlua_function *fcn = NULL;
	int index;
	int i;
	struct buffer *trash;
	const char *kw[5];
	struct cli_kw *cli_kw;
	const char *errmsg;
	char *end;

	MAY_LJMP(check_args(L, 3, "register_cli"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_cli: not available outside of body context"));
	}

	/* First argument : an array of maximum 5 keywords. */
	if (!lua_istable(L, 1))
		WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table"));

	/* Second argument : string with contextual message. */
	message = MAY_LJMP(luaL_checkstring(L, 2));

	/* Third and fourth argument : lua function. */
	ref_io = MAY_LJMP(hlua_checkfunction(L, 3));

	/* Check for CLI service already registered */
	trash = get_trash_chunk();
	index = 0;
	lua_pushnil(L);
	memset(kw, 0, sizeof(kw));
	while (lua_next(L, 1) != 0) {
		if (index >= CLI_PREFIX_KW_NB) {
			hlua_unref(L, ref_io);
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table with a maximum of 5 entries"));
		}
		if (lua_type(L, -1) != LUA_TSTRING) {
			hlua_unref(L, ref_io);
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table filled with strings"));
		}
		kw[index] = lua_tostring(L, -1);
		if (index == 0)
			chunk_printf(trash, "%s", kw[index]);
		else
			chunk_appendf(trash, " %s", kw[index]);
		index++;
		lua_pop(L, 1);
	}
	cli_kw = cli_find_kw_exact((char **)kw);
	if (cli_kw != NULL) {
		fcn = cli_kw->private;
		if (fcn->function_ref[hlua_state_id] != -1) {
			ha_warning("Trying to register CLI keyword 'lua.%s' more than once. "
			           "This will become a hard error in version 2.5.\n", trash->area);
			hlua_unref(L, fcn->function_ref[hlua_state_id]);
		}
		fcn->function_ref[hlua_state_id] = ref_io;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	cli_kws = calloc(1, sizeof(*cli_kws) + sizeof(struct cli_kw) * 2);
	if (!cli_kws) {
		errmsg = "Lua out of memory error.";
		goto error;
	}
	fcn = new_hlua_function();
	if (!fcn) {
		errmsg = "Lua out of memory error.";
		goto error;
	}

	/* Fill path. */
	index = 0;
	lua_pushnil(L);
	while(lua_next(L, 1) != 0) {
		if (index >= 5) {
			errmsg = "1st argument must be a table with a maximum of 5 entries";
			goto error;
		}
		if (lua_type(L, -1) != LUA_TSTRING) {
			errmsg = "1st argument must be a table filled with strings";
			goto error;
		}
		cli_kws->kw[0].str_kw[index] = strdup(lua_tostring(L, -1));
		if (!cli_kws->kw[0].str_kw[index]) {
			errmsg = "Lua out of memory error.";
			goto error;
		}
		index++;
		lua_pop(L, 1);
	}

	/* Copy help message. */
	cli_kws->kw[0].usage = strdup(message);
	if (!cli_kws->kw[0].usage) {
		errmsg = "Lua out of memory error.";
		goto error;
	}

	/* Fill fcn io handler. */
	len = strlen("<lua.cli>") + 1;
	for (i = 0; i < index; i++)
		len += strlen(cli_kws->kw[0].str_kw[i]) + 1;
	fcn->name = calloc(1, len);
	if (!fcn->name) {
		errmsg = "Lua out of memory error.";
		goto error;
	}

	end = fcn->name;
	len = 8;
	memcpy(end, "<lua.cli", len);
	end += len;

	for (i = 0; i < index; i++) {
		*(end++) = '.';
		len = strlen(cli_kws->kw[0].str_kw[i]);
		memcpy(end, cli_kws->kw[0].str_kw[i], len);
		end += len;
	}
	*(end++) = '>';
	*(end++) = 0;

	fcn->function_ref[hlua_state_id] = ref_io;

	/* Fill last entries. */
	cli_kws->kw[0].private = fcn;
	cli_kws->kw[0].parse = hlua_cli_parse_fct;
	cli_kws->kw[0].io_handler = hlua_cli_io_handler_fct;
	cli_kws->kw[0].io_release = hlua_cli_io_release_fct;

	/* Register this new converter */
	cli_register_kw(cli_kws);

	return 0;

  error:
	release_hlua_function(fcn);
	hlua_unref(L, ref_io);
	if (cli_kws) {
		for (i = 0; i < index; i++)
			ha_free((char **)&(cli_kws->kw[0].str_kw[i]));
		ha_free((char **)&(cli_kws->kw[0].usage));
	}
	ha_free(&cli_kws);
	WILL_LJMP(luaL_error(L, errmsg));
	return 0; /* Never reached */
}

static int hlua_filter_init_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	struct hlua_flt_config *conf = fconf->conf;
	lua_State *L;
	int error, pos, state_id, flt_ref;

	state_id = reg_flt_to_stack_id(conf->reg);
	L = hlua_states[state_id];
	pos = lua_gettop(L);

	/* The filter parsing function */
	hlua_pushref(L, conf->reg->fun_ref[state_id]);

	/* Push the filter class on the stack and resolve all callbacks */
	hlua_pushref(L, conf->reg->flt_ref[state_id]);

	/* Duplicate the filter class so each filter will have its own copy */
	lua_newtable(L);
	lua_pushnil(L);

        while (lua_next(L, pos+2)) {
		lua_pushvalue(L, -2);
		lua_insert(L, -2);
		lua_settable(L, -4);
	}
	flt_ref = hlua_ref(L);

	/* Remove the original lua filter class from the stack */
	lua_pop(L, 1);

	/* Push the copy on the stack */
	hlua_pushref(L, flt_ref);

	/* extra args are pushed in a table */
	lua_newtable(L);
	for (pos = 0; conf->args[pos]; pos++) {
		/* Check stack available size. */
		if (!lua_checkstack(L, 1)) {
			ha_alert("Lua filter '%s' : Lua error : full stack.", conf->reg->name);
			goto error;
		}
		lua_pushstring(L, conf->args[pos]);
		lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
	}

	error = lua_pcall(L, 2, LUA_MULTRET, 0);
	switch (error) {
	case LUA_OK:
		/* replace the filter ref */
		conf->ref[state_id] = flt_ref;
		break;
	case LUA_ERRRUN:
		ha_alert("Lua filter '%s' : runtime error : %s", conf->reg->name, hlua_tostring_safe(L, -1));
		goto error;
	case LUA_ERRMEM:
		ha_alert("Lua filter '%s' : out of memory error", conf->reg->name);
		goto error;
	case LUA_ERRERR:
		ha_alert("Lua filter '%s' : message handler error : %s", conf->reg->name, hlua_tostring_safe(L, -1));
		goto error;
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 503
	case LUA_ERRGCMM:
		ha_alert("Lua filter '%s' : garbage collector error : %s", conf->reg->name, hlua_tostring_safe(L, -1));
		goto error;
#endif
	default:
		ha_alert("Lua filter '%s' : unknown error : %s", conf->reg->name, hlua_tostring_safe(L, -1));
		goto error;
	}

	lua_settop(L, 0);
	return 0;

  error:
	lua_settop(L, 0);
	return -1;
}

static void hlua_filter_deinit_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	struct hlua_flt_config *conf = fconf->conf;
	lua_State *L;
	int state_id;

	if (!conf)
		return;

	state_id = reg_flt_to_stack_id(conf->reg);
	L = hlua_states[state_id];
	hlua_unref(L, conf->ref[state_id]);
}

static int hlua_filter_init(struct proxy *px, struct flt_conf *fconf)
{
	struct hlua_flt_config *conf = fconf->conf;
	int state_id = reg_flt_to_stack_id(conf->reg);

	/* Rely on per-thread init for global scripts */
	if (!state_id)
		return hlua_filter_init_per_thread(px, fconf);
	return 0;
}

static void hlua_filter_deinit(struct proxy *px, struct flt_conf *fconf)
{

	if (fconf->conf) {
		struct hlua_flt_config *conf = fconf->conf;
		int state_id = reg_flt_to_stack_id(conf->reg);
		int pos;

		/* Rely on per-thread deinit for global scripts */
		if (!state_id)
			hlua_filter_deinit_per_thread(px, fconf);

		for (pos = 0; conf->args[pos]; pos++)
			free(conf->args[pos]);
		free(conf->args);
	}
	ha_free(&fconf->conf);
	ha_free((char **)&fconf->id);
	ha_free(&fconf->ops);
}

static int hlua_filter_new(struct stream *s, struct filter *filter)
{
	struct hlua_flt_config *conf = FLT_CONF(filter);
	struct hlua_flt_ctx *flt_ctx = NULL;
	struct hlua *hlua = NULL;
	int ret = 1;

	if (!(hlua = hlua_stream_ctx_prepare(s, reg_flt_to_stack_id(conf->reg)))) {
		SEND_ERR(s->be, "Lua filter '%s': can't initialize filter Lua context.\n",
			 conf->reg->name);
		ret = 0;
		goto end;
	}

	flt_ctx = pool_zalloc(pool_head_hlua_flt_ctx);
	if (!flt_ctx) {
		SEND_ERR(s->be, "Lua filter '%s': can't initialize filter Lua context.\n",
			 conf->reg->name);
		ret = 0;
		goto end;
	}

	if ((flt_ctx->hlua[0] = pool_alloc(pool_head_hlua)))
		HLUA_INIT(flt_ctx->hlua[0]);
	if ((flt_ctx->hlua[1] = pool_alloc(pool_head_hlua)))
		HLUA_INIT(flt_ctx->hlua[1]);
	if (!flt_ctx->hlua[0] || !flt_ctx->hlua[1]) {
		SEND_ERR(s->be, "Lua filter '%s': can't initialize filter Lua context.\n",
			 conf->reg->name);
		ret = 0;
		goto end;
	}

	if (!hlua_ctx_init(flt_ctx->hlua[0], reg_flt_to_stack_id(conf->reg), s->task) ||
	    !hlua_ctx_init(flt_ctx->hlua[1], reg_flt_to_stack_id(conf->reg), s->task)) {
		SEND_ERR(s->be, "Lua filter '%s': can't initialize filter Lua context.\n",
			 conf->reg->name);
		ret = 0;
		goto end;
	}

	if (!HLUA_IS_RUNNING(hlua)) {
		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua)) {
			const char *error;

			hlua_lock(hlua);
			if (lua_type(hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(s->be, "Lua filter '%s': %s.\n", conf->reg->name, error);
			hlua_unlock(hlua);
			ret = 0;
			goto end;
		}

		/* Check stack size. */
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(s->be, "Lua filter '%s': full stack.\n", conf->reg->name);
			RESET_SAFE_LJMP(hlua);
			ret = 0;
			goto end;
		}

		hlua_pushref(hlua->T, conf->ref[hlua->state_id]);
		if (lua_getfield(hlua->T, -1, "new") != LUA_TFUNCTION) {
			SEND_ERR(s->be, "Lua filter '%s': 'new' field is not a function.\n",
				 conf->reg->name);
			RESET_SAFE_LJMP(hlua);
			ret = 0;
			goto end;
		}
		lua_insert(hlua->T, -2);

		/* Push the copy on the stack */
		hlua->nargs = 1;

		/* We must initialize the execution timeouts. */
		hlua_timer_init(&hlua->timer, hlua_timeout_session);

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(hlua);
	}

	switch (hlua_ctx_resume(hlua, 0)) {
	case HLUA_E_OK:
		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(hlua)) {
			const char *error;

			hlua_lock(hlua);
			if (lua_type(hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(s->be, "Lua filter '%s': %s.\n", conf->reg->name, error);
			hlua_unlock(hlua);
			ret = 0;
			goto end;
		}

		/* Nothing returned or not a table, ignore the filter for current stream */
		if (!lua_gettop(hlua->T) || !lua_istable(hlua->T, 1)) {
			ret = 0;
			RESET_SAFE_LJMP(hlua);
			goto end;
		}

		/* Attached the filter pointer to the ctx */
		lua_pushstring(hlua->T, "__filter");
		lua_pushlightuserdata(hlua->T, filter);
		lua_settable(hlua->T, -3);

		/* Save a ref on the filter ctx */
		lua_pushvalue(hlua->T, 1);
		flt_ctx->ref = hlua_ref(hlua->T);

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(hlua);

		/* save main hlua ctx (from the stream) */
		flt_ctx->_hlua = hlua;

		filter->ctx = flt_ctx;
		break;
	case HLUA_E_ERRMSG:
		hlua_lock(hlua);
		SEND_ERR(s->be, "Lua filter '%s' : %s.\n", conf->reg->name, hlua_tostring_safe(hlua->T, -1));
		hlua_unlock(hlua);
		ret = -1;
		goto end;
	case HLUA_E_ETMOUT:
		SEND_ERR(s->be, "Lua filter '%s' : 'new' execution timeout.\n", conf->reg->name);
		ret = 0;
		goto end;
	case HLUA_E_BTMOUT:
		SEND_ERR(s->be, "Lua filter '%s' : 'new' burst timeout.\n", conf->reg->name);
		ret = 0;
		goto end;
	case HLUA_E_NOMEM:
		SEND_ERR(s->be, "Lua filter '%s' : out of memory error.\n", conf->reg->name);
		ret = 0;
		goto end;
	case HLUA_E_AGAIN:
	case HLUA_E_YIELD:
		SEND_ERR(s->be, "Lua filter '%s': yield functions like core.tcp() or core.sleep()"
			 " are not allowed from 'new' function.\n", conf->reg->name);
		ret = 0;
		goto end;
	case HLUA_E_ERR:
		SEND_ERR(s->be, "Lua filter '%s': 'new' returns an unknown error.\n", conf->reg->name);
		ret = 0;
		goto end;
	default:
		ret = 0;
		goto end;
	}

  end:
	if (hlua) {
		hlua_lock(hlua);
		lua_settop(hlua->T, 0);
		hlua_unlock(hlua);
	}
	if (ret <= 0) {
		if (flt_ctx) {
			hlua_ctx_destroy(flt_ctx->hlua[0]);
			hlua_ctx_destroy(flt_ctx->hlua[1]);
			pool_free(pool_head_hlua_flt_ctx, flt_ctx);
		}
	}
	return ret;
}

static void hlua_filter_delete(struct stream *s, struct filter *filter)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;
	struct hlua *hlua = hlua_stream_ctx_get(s, flt_ctx->_hlua->state_id);

	hlua_lock(hlua);
	hlua_unref(hlua->T, flt_ctx->ref);
	hlua_unlock(hlua);
	hlua_ctx_destroy(flt_ctx->hlua[0]);
	hlua_ctx_destroy(flt_ctx->hlua[1]);
	pool_free(pool_head_hlua_flt_ctx, flt_ctx);
	filter->ctx = NULL;
}

static int hlua_filter_from_payload(struct filter *filter)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;

	return (flt_ctx && !!(flt_ctx->flags & HLUA_FLT_CTX_FL_PAYLOAD));
}

static int hlua_filter_callback(struct stream *s, struct filter *filter, const char *fun,
				int dir, unsigned int flags)
{
	struct hlua *flt_hlua;
	struct hlua_flt_config *conf = FLT_CONF(filter);
	struct hlua_flt_ctx *flt_ctx = filter->ctx;
	unsigned int hflags = HLUA_TXN_FLT_CTX;
	int ret = 1;

	flt_hlua = flt_ctx->hlua[(dir == SMP_OPT_DIR_REQ ? 0 : 1)];
	if (!flt_hlua)
		goto end;

	if (!HLUA_IS_RUNNING(flt_hlua)) {
		int extra_idx;

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(flt_hlua)) {
			const char *error;

			hlua_lock(flt_hlua);
			if (lua_type(flt_hlua->T, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(flt_hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(s->be, "Lua filter '%s': %s.\n", conf->reg->name, error);
			hlua_unlock(flt_hlua);
			goto end;
		}

		extra_idx = lua_gettop(flt_hlua->T);

		/* Check stack size. */
		if (!lua_checkstack(flt_hlua->T, 3)) {
			SEND_ERR(s->be, "Lua filter '%s': full stack.\n", conf->reg->name);
			RESET_SAFE_LJMP(flt_hlua);
			goto end;
		}

		hlua_pushref(flt_hlua->T, flt_ctx->ref);
		if (lua_getfield(flt_hlua->T, -1, fun) != LUA_TFUNCTION) {
			RESET_SAFE_LJMP(flt_hlua);
			goto end;
		}
		lua_insert(flt_hlua->T, -2);

		if (!hlua_txn_new(flt_hlua->T, s, s->be, dir, hflags)) {
			SEND_ERR(s->be, "Lua filter '%s': full stack.\n", conf->reg->name);
			RESET_SAFE_LJMP(flt_hlua);
			goto end;
		}
		flt_hlua->nargs = 2;

		if (flags & HLUA_FLT_CB_ARG_CHN) {
			if (dir == SMP_OPT_DIR_REQ)
				lua_getfield(flt_hlua->T, -1, "req");
			else
				lua_getfield(flt_hlua->T, -1, "res");
			if (lua_type(flt_hlua->T, -1) == LUA_TTABLE) {
				lua_pushstring(flt_hlua->T, "__filter");
				lua_pushlightuserdata(flt_hlua->T, filter);
				lua_settable(flt_hlua->T, -3);
			}
			flt_hlua->nargs++;
		}
		else if (flags & HLUA_FLT_CB_ARG_HTTP_MSG) {
			if (dir == SMP_OPT_DIR_REQ)
				lua_getfield(flt_hlua->T, -1, "http_req");
			else
				lua_getfield(flt_hlua->T, -1, "http_res");
			if (lua_type(flt_hlua->T, -1) == LUA_TTABLE) {
				lua_pushstring(flt_hlua->T, "__filter");
				lua_pushlightuserdata(flt_hlua->T, filter);
				lua_settable(flt_hlua->T, -3);
			}
			flt_hlua->nargs++;
		}

		/* Check stack size. */
		if (!lua_checkstack(flt_hlua->T, 1)) {
			SEND_ERR(s->be, "Lua filter '%s': full stack.\n", conf->reg->name);
			RESET_SAFE_LJMP(flt_hlua);
			goto end;
		}

		while (extra_idx--) {
			lua_pushvalue(flt_hlua->T, 1);
			lua_remove(flt_hlua->T, 1);
			flt_hlua->nargs++;
		}

		/* We must initialize the execution timeouts. */
		hlua_timer_init(&flt_hlua->timer, hlua_timeout_session);

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(flt_hlua);
	}

	switch (hlua_ctx_resume(flt_hlua, !(flags & HLUA_FLT_CB_FINAL))) {
	case HLUA_E_OK:
		/* Catch the return value if it required */
		hlua_lock(flt_hlua);
		if ((flags & HLUA_FLT_CB_RETVAL) && lua_gettop(flt_hlua->T) > 0) {
			ret = lua_tointeger(flt_hlua->T, -1);
			lua_settop(flt_hlua->T, 0); /* Empty the stack. */
		}
		hlua_unlock(flt_hlua);

		/* Set timeout in the required channel. */
		if (flt_hlua->wake_time != TICK_ETERNITY) {
			if (dir == SMP_OPT_DIR_REQ)
				s->req.analyse_exp = flt_hlua->wake_time;
			else
				s->res.analyse_exp = flt_hlua->wake_time;
		}
		break;
	case HLUA_E_AGAIN:
		/* Set timeout in the required channel. */
		if (flt_hlua->wake_time != TICK_ETERNITY) {
			if (dir == SMP_OPT_DIR_REQ)
				s->req.analyse_exp = flt_hlua->wake_time;
			else
				s->res.analyse_exp = flt_hlua->wake_time;
		}
		/* Some actions can be wake up when a "write" event
		 * is detected on a response channel. This is useful
		 * only for actions targeted on the requests.
		 */
		if (HLUA_IS_WAKERESWR(flt_hlua))
			s->res.flags |= CF_WAKE_WRITE;
		if (HLUA_IS_WAKEREQWR(flt_hlua))
			s->req.flags |= CF_WAKE_WRITE;
		ret = 0;
		goto end;
	case HLUA_E_ERRMSG:
		hlua_lock(flt_hlua);
		SEND_ERR(s->be, "Lua filter '%s' : %s.\n", conf->reg->name, hlua_tostring_safe(flt_hlua->T, -1));
		hlua_unlock(flt_hlua);
		ret = -1;
		goto end;
	case HLUA_E_ETMOUT:
		SEND_ERR(s->be, "Lua filter '%s' : '%s' callback execution timeout.\n", conf->reg->name, fun);
		goto end;
	case HLUA_E_BTMOUT:
		SEND_ERR(s->be, "Lua filter '%s' : '%s' callback burst timeout.\n", conf->reg->name, fun);
		goto end;
	case HLUA_E_NOMEM:
		SEND_ERR(s->be, "Lua filter '%s' : out of memory error.\n", conf->reg->name);
		goto end;
	case HLUA_E_YIELD:
		SEND_ERR(s->be, "Lua filter '%s': yield functions like core.tcp() or core.sleep()"
			 " are not allowed from '%s' callback.\n", conf->reg->name, fun);
		goto end;
	case HLUA_E_ERR:
		SEND_ERR(s->be, "Lua filter '%s': '%s' returns an unknown error.\n", conf->reg->name, fun);
		goto end;
	default:
		goto end;
	}


  end:
	return ret;
}

static int  hlua_filter_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;

	flt_ctx->flags = 0;
	return hlua_filter_callback(s, filter, "start_analyze",
				    (!(chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES),
				    (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_RETVAL | HLUA_FLT_CB_ARG_CHN));
}

static int  hlua_filter_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;

	flt_ctx->flags &= ~HLUA_FLT_CTX_FL_PAYLOAD;
	return hlua_filter_callback(s, filter, "end_analyze",
				    (!(chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES),
				    (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_RETVAL | HLUA_FLT_CB_ARG_CHN));
}

static int  hlua_filter_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;

	flt_ctx->flags &= ~HLUA_FLT_CTX_FL_PAYLOAD;
	return hlua_filter_callback(s, filter, "http_headers",
				    (!(msg->chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES),
				    (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_RETVAL | HLUA_FLT_CB_ARG_HTTP_MSG));
}

static int  hlua_filter_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
				     unsigned int offset, unsigned int len)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;
	struct hlua *flt_hlua;
	int dir = (!(msg->chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES);
	int idx = (dir == SMP_OPT_DIR_REQ ? 0 : 1);
	int ret;

	flt_hlua = flt_ctx->hlua[idx];
	flt_ctx->cur_off[idx] = offset;
	flt_ctx->cur_len[idx] = len;
	flt_ctx->flags |= HLUA_FLT_CTX_FL_PAYLOAD;
	ret = hlua_filter_callback(s, filter, "http_payload", dir, (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_ARG_HTTP_MSG));
	if (ret != -1) {
		ret = flt_ctx->cur_len[idx];
		if (lua_gettop(flt_hlua->T) > 0) {
			ret = lua_tointeger(flt_hlua->T, -1);
			if (ret > flt_ctx->cur_len[idx])
				ret = flt_ctx->cur_len[idx];
			lua_settop(flt_hlua->T, 0); /* Empty the stack. */
		}
	}
	return ret;
}

static int  hlua_filter_http_end(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;

	flt_ctx->flags &= ~HLUA_FLT_CTX_FL_PAYLOAD;
	return hlua_filter_callback(s, filter, "http_end",
				    (!(msg->chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES),
				    (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_RETVAL | HLUA_FLT_CB_ARG_HTTP_MSG));
}

static int  hlua_filter_tcp_payload(struct stream *s, struct filter *filter, struct channel *chn,
				    unsigned int offset, unsigned int len)
{
	struct hlua_flt_ctx *flt_ctx = filter->ctx;
	struct hlua *flt_hlua;
	int dir = (!(chn->flags & CF_ISRESP) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES);
	int idx = (dir == SMP_OPT_DIR_REQ ? 0 : 1);
	int ret;

	flt_hlua = flt_ctx->hlua[idx];
	flt_ctx->cur_off[idx] = offset;
	flt_ctx->cur_len[idx] = len;
	flt_ctx->flags |= HLUA_FLT_CTX_FL_PAYLOAD;
	ret = hlua_filter_callback(s, filter, "tcp_payload", dir, (HLUA_FLT_CB_FINAL | HLUA_FLT_CB_ARG_CHN));
	if (ret != -1) {
		ret = flt_ctx->cur_len[idx];
		if (lua_gettop(flt_hlua->T) > 0) {
			ret = lua_tointeger(flt_hlua->T, -1);
			if (ret > flt_ctx->cur_len[idx])
				ret = flt_ctx->cur_len[idx];
			lua_settop(flt_hlua->T, 0); /* Empty the stack. */
		}
	}
	return ret;
}

static int hlua_filter_parse_fct(char **args, int *cur_arg, struct proxy *px,
				 struct flt_conf *fconf, char **err, void *private)
{
	struct hlua_reg_filter *reg_flt = private;
	lua_State *L;
	struct hlua_flt_config *conf = NULL;
	const char *flt_id = NULL;
	int state_id, pos, flt_flags = 0;
	struct flt_ops *hlua_flt_ops = NULL;

	state_id = reg_flt_to_stack_id(reg_flt);
	L = hlua_states[state_id];

	/* Initialize the filter ops with default callbacks */
	hlua_flt_ops = calloc(1, sizeof(*hlua_flt_ops));
	if (!hlua_flt_ops)
		goto error;
	hlua_flt_ops->init              = hlua_filter_init;
	hlua_flt_ops->deinit            = hlua_filter_deinit;
	if (state_id) {
		/* Set per-thread callback if script is loaded per-thread */
		hlua_flt_ops->init_per_thread   = hlua_filter_init_per_thread;
		hlua_flt_ops->deinit_per_thread = hlua_filter_deinit_per_thread;
	}
	hlua_flt_ops->attach            = hlua_filter_new;
	hlua_flt_ops->detach            = hlua_filter_delete;

	/* Push the filter class on the stack and resolve all callbacks */
	hlua_pushref(L, reg_flt->flt_ref[state_id]);

	if (lua_getfield(L, -1, "start_analyze") == LUA_TFUNCTION)
		hlua_flt_ops->channel_start_analyze = hlua_filter_start_analyze;
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "end_analyze") == LUA_TFUNCTION)
		hlua_flt_ops->channel_end_analyze = hlua_filter_end_analyze;
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "http_headers") == LUA_TFUNCTION)
		hlua_flt_ops->http_headers = hlua_filter_http_headers;
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "http_payload") == LUA_TFUNCTION)
		hlua_flt_ops->http_payload = hlua_filter_http_payload;
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "http_end") == LUA_TFUNCTION)
		hlua_flt_ops->http_end = hlua_filter_http_end;
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "tcp_payload") == LUA_TFUNCTION)
		hlua_flt_ops->tcp_payload = hlua_filter_tcp_payload;
	lua_pop(L, 1);

	/* Get id and flags of the filter class */
	if (lua_getfield(L, -1, "id") == LUA_TSTRING)
		flt_id  = lua_tostring(L, -1);
	lua_pop(L, 1);
	if (lua_getfield(L, -1, "flags") == LUA_TNUMBER)
		flt_flags  = lua_tointeger(L, -1);
	lua_pop(L, 1);

	/* Create the filter config */
	conf = calloc(1, sizeof(*conf));
	if (!conf)
		goto error;
	conf->reg = reg_flt;

	/* duplicate args */
	for (pos = 0; *args[*cur_arg + 1 + pos]; pos++);
	conf->args = calloc(pos + 1, sizeof(*conf->args));
	if (!conf->args)
		goto error;
	for (pos = 0; *args[*cur_arg + 1 + pos]; pos++) {
		conf->args[pos] = strdup(args[*cur_arg + 1 + pos]);
		if (!conf->args[pos])
			goto error;
	}
	conf->args[pos] = NULL;
	*cur_arg += pos + 1;

	if (flt_id) {
		fconf->id    = strdup(flt_id);
		if (!fconf->id)
			goto error;
	}
	fconf->flags = flt_flags;
	fconf->conf  = conf;
	fconf->ops   = hlua_flt_ops;

	lua_settop(L, 0);
	return 0;

  error:
	memprintf(err, "Lua filter '%s' : Lua out of memory error", reg_flt->name);
	free(hlua_flt_ops);
	if (conf && conf->args) {
		for (pos = 0; conf->args[pos]; pos++)
			free(conf->args[pos]);
		free(conf->args);
	}
	free(conf);
	free((char *)fconf->id);
	lua_settop(L, 0);
	return -1;
}

__LJMP static int hlua_register_data_filter(lua_State *L)
{
	struct filter *filter;
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "register_data_filter"));
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));
	chn = MAY_LJMP(hlua_checkchannel(L, 2));

	lua_getfield(L, 1, "__filter");
	MAY_LJMP(luaL_checktype(L, -1, LUA_TLIGHTUSERDATA));
	filter = lua_touserdata (L, -1);
	lua_pop(L, 1);

	register_data_filter(chn_strm(chn), chn, filter);
	return 1;
}

__LJMP static int hlua_unregister_data_filter(lua_State *L)
{
	struct filter *filter;
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "unregister_data_filter"));
	MAY_LJMP(luaL_checktype(L, 1, LUA_TTABLE));
	chn = MAY_LJMP(hlua_checkchannel(L, 2));

	lua_getfield(L, 1, "__filter");
	MAY_LJMP(luaL_checktype(L, -1, LUA_TLIGHTUSERDATA));
	filter = lua_touserdata (L, -1);
	lua_pop(L, 1);

	unregister_data_filter(chn_strm(chn), chn, filter);
	return 1;
}

/* This function is an LUA binding used for registering a filter. It expects a
 * filter name used in the haproxy configuration file and a LUA function to
 * parse configuration arguments.
 */
__LJMP static int hlua_register_filter(lua_State *L)
{
	struct buffer *trash;
	struct flt_kw_list *fkl;
	struct flt_kw *fkw;
	const char *name;
	struct hlua_reg_filter *reg_flt= NULL;
	int flt_ref, fun_ref;
	int len;

	MAY_LJMP(check_args(L, 3, "register_filter"));

	if (hlua_gethlua(L)) {
		/* runtime processing */
		WILL_LJMP(luaL_error(L, "register_filter: not available outside of body context"));
	}

	/* First argument : filter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : The filter class */
	flt_ref = MAY_LJMP(hlua_checktable(L, 2));

	/* Third argument : lua function. */
	fun_ref = MAY_LJMP(hlua_checkfunction(L, 3));

	trash = get_trash_chunk();
	chunk_printf(trash, "lua.%s", name);
	fkw = flt_find_kw(trash->area);
	if (fkw != NULL) {
		reg_flt = fkw->private;
		if (reg_flt->flt_ref[hlua_state_id] != -1 ||  reg_flt->fun_ref[hlua_state_id] != -1) {
			ha_warning("Trying to register filter 'lua.%s' more than once. "
				   "This will become a hard error in version 2.5.\n", name);
			if (reg_flt->flt_ref[hlua_state_id] != -1)
				hlua_unref(L, reg_flt->flt_ref[hlua_state_id]);
			if (reg_flt->fun_ref[hlua_state_id] != -1)
				hlua_unref(L, reg_flt->fun_ref[hlua_state_id]);
		}
		reg_flt->flt_ref[hlua_state_id] = flt_ref;
		reg_flt->fun_ref[hlua_state_id] = fun_ref;
		return 0;
	}

	fkl = calloc(1, sizeof(*fkl) + sizeof(struct flt_kw) * 2);
	if (!fkl)
		goto alloc_error;
	fkl->scope = "HLUA";

	reg_flt = new_hlua_reg_filter(name);
	if (!reg_flt)
		goto alloc_error;

	reg_flt->flt_ref[hlua_state_id] = flt_ref;
	reg_flt->fun_ref[hlua_state_id] = fun_ref;

	/* The filter keyword */
	len = strlen("lua.") + strlen(name) + 1;
	fkl->kw[0].kw = calloc(1, len);
	if (!fkl->kw[0].kw)
		goto alloc_error;

	snprintf((char *)fkl->kw[0].kw, len, "lua.%s", name);

	fkl->kw[0].parse = hlua_filter_parse_fct;
	fkl->kw[0].private = reg_flt;
	memset(&fkl->kw[1], 0, sizeof(*fkl->kw));

	/* Register this new filter */
	flt_register_keywords(fkl);

	return 0;

  alloc_error:
	release_hlua_reg_filter(reg_flt);
	hlua_unref(L, flt_ref);
	hlua_unref(L, fun_ref);
	ha_free(&fkl);
	WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	return 0; /* Never reached */
}

static int hlua_read_timeout(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err, unsigned int *timeout)
{
	const char *error;

	error = parse_time_err(args[1], timeout, TIME_UNIT_MS);
	if (error == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument <%s> to <%s> (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (error == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument <%s> to <%s> (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (error) {
		memprintf(err, "%s: invalid timeout", args[0]);
		return -1;
	}
	return 0;
}

static int hlua_burst_timeout(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_burst);
}

static int hlua_session_timeout(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_session);
}

static int hlua_task_timeout(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_task);
}

static int hlua_applet_timeout(char **args, int section_type, struct proxy *curpx,
                               const struct proxy *defpx, const char *file, int line,
                               char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_applet);
}

static int hlua_forced_yield(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	char *error;

	hlua_nb_instruction = strtoll(args[1], &error, 10);
	if (*error != '\0') {
		memprintf(err, "%s: invalid number", args[0]);
		return -1;
	}
	return 0;
}

static int hlua_parse_maxmem(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	char *error;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument (Lua memory size in MB).", args[0]);
		return -1;
	}
	hlua_global_allocator.limit = strtoll(args[1], &error, 10) * 1024L * 1024L;
	if (*error != '\0') {
		memprintf(err, "%s: invalid number %s (error at '%c')", args[0], args[1], *error);
		return -1;
	}
	return 0;
}

static int hlua_cfg_parse_log_loggers(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		hlua_log_opts |= HLUA_LOG_LOGGERS_ON;
	else if (strcmp(args[1], "off") == 0)
		hlua_log_opts &= ~HLUA_LOG_LOGGERS_ON;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

static int hlua_cfg_parse_log_stderr(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		hlua_log_opts = (hlua_log_opts & ~HLUA_LOG_STDERR_MASK) | HLUA_LOG_STDERR_ON;
	else if (strcmp(args[1], "auto") == 0)
		hlua_log_opts = (hlua_log_opts & ~HLUA_LOG_STDERR_MASK) | HLUA_LOG_STDERR_AUTO;
	else if (strcmp(args[1], "off") == 0)
		hlua_log_opts &= ~HLUA_LOG_STDERR_MASK;
	else {
		memprintf(err, "'%s' expects either 'on', 'auto', or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* This function is called by the main configuration key "lua-load". It loads and
 * execute an lua file during the parsing of the HAProxy configuration file. It is
 * the main lua entry point.
 *
 * This function runs with the HAProxy keywords API. It returns -1 if an error
 * occurs, otherwise it returns 0.
 *
 * In some error case, LUA set an error message in top of the stack. This function
 * returns this error message in the HAProxy logs and pop it from the stack.
 *
 * This function can fail with an abort() due to an Lua critical error.
 * We are in the configuration parsing process of HAProxy, this abort() is
 * tolerated.
 */
static int hlua_load_state(char **args, lua_State *L, char **err)
{
	int error;
	int nargs;

	/* Just load and compile the file. */
	error = luaL_loadfile(L, args[0]);
	if (error) {
		memprintf(err, "error in Lua file '%s': %s", args[0], hlua_tostring_safe(L, -1));
		lua_pop(L, 1);
		return -1;
	}

	/* Push args in the Lua stack, except the first one which is the filename */
	for (nargs = 1; *(args[nargs]) != 0; nargs++) {
		/* Check stack size. */
		if (!lua_checkstack(L, 1)) {
			memprintf(err, "Lua runtime error while loading arguments: stack is full.");
			return -1;
		}
		lua_pushstring(L, args[nargs]);
	}
	nargs--;

	/* If no syntax error where detected, execute the code. */
	error = lua_pcall(L, nargs, LUA_MULTRET, 0);
	switch (error) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		memprintf(err, "Lua runtime error: %s", hlua_tostring_safe(L, -1));
		lua_pop(L, 1);
		return -1;
	case LUA_ERRMEM:
		memprintf(err, "Lua out of memory error");
		return -1;
	case LUA_ERRERR:
		memprintf(err, "Lua message handler error: %s", hlua_tostring_safe(L, -1));
		lua_pop(L, 1);
		return -1;
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 503
	case LUA_ERRGCMM:
		memprintf(err, "Lua garbage collector error: %s", hlua_tostring_safe(L, -1));
		lua_pop(L, 1);
		return -1;
#endif
	default:
		memprintf(err, "Lua unknown error: %s", hlua_tostring_safe(L, -1));
		lua_pop(L, 1);
		return -1;
	}

	return 0;
}

static int hlua_load(char **args, int section_type, struct proxy *curpx,
                     const struct proxy *defpx, const char *file, int line,
                     char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file name as parameter.", args[0]);
		return -1;
	}

	/* loading for global state */
	hlua_state_id = 0;
	ha_set_thread(NULL);
	return hlua_load_state(&args[1], hlua_states[0], err);
}

static int hlua_load_per_thread(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	int len;
	int i;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file as parameter.", args[0]);
		return -1;
	}

	if (per_thread_load == NULL) {
		/* allocate the first entry large enough to store the final NULL */
		per_thread_load = calloc(1, sizeof(*per_thread_load));
		if (per_thread_load == NULL) {
			memprintf(err, "out of memory error");
			return -1;
		}
	}

	/* count used entries */
	for (len = 0; per_thread_load[len] != NULL; len++)
		;

	per_thread_load = realloc(per_thread_load, (len + 2) * sizeof(*per_thread_load));
	if (per_thread_load == NULL) {
		memprintf(err, "out of memory error");
		return -1;
	}
	per_thread_load[len + 1] = NULL;

	/* count args excepting the first, allocate array and copy args */
	for (i = 0; *(args[i + 1]) != 0; i++);
	per_thread_load[len] = calloc(i + 1, sizeof(*per_thread_load[len]));
	if (per_thread_load[len] == NULL) {
		memprintf(err, "out of memory error");
		return -1;
	}
	for (i = 1; *(args[i]) != 0; i++) {
		per_thread_load[len][i - 1] = strdup(args[i]);
		if (per_thread_load[len][i - 1] == NULL) {
			memprintf(err, "out of memory error");
			return -1;
		}
	}
	per_thread_load[len][i - 1] = strdup("");
	if (per_thread_load[len][i - 1]  == NULL) {
		memprintf(err, "out of memory error");
		return -1;
	}

	/* loading for thread 1 only */
	hlua_state_id = 1;
	ha_set_thread(NULL);
	return hlua_load_state(per_thread_load[len], hlua_states[1], err);
}

/* Prepend the given <path> followed by a semicolon to the `package.<type>` variable
 * in the given <ctx>.
 */
static int hlua_prepend_path(lua_State *L, char *type, char *path)
{
	lua_getglobal(L, "package"); /* push package variable   */
	lua_pushstring(L, path);     /* push given path         */
	lua_pushstring(L, ";");      /* push semicolon          */
	lua_getfield(L, -3, type);   /* push old path           */
	lua_concat(L, 3);            /* concatenate to new path */
	lua_setfield(L, -2, type);   /* store new path          */
	lua_pop(L, 1);               /* pop package variable    */

	return 0;
}

static int hlua_config_prepend_path(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	char *path;
	char *type = "path";
	struct prepend_path *p = NULL;
	size_t i;

	if (too_many_args(2, args, err, NULL)) {
		goto err;
	}

	if (!(*args[1])) {
		memprintf(err, "'%s' expects to receive a <path> as argument", args[0]);
		goto err;
	}
	path = args[1];

	if (*args[2]) {
		if (strcmp(args[2], "path") != 0 && strcmp(args[2], "cpath") != 0) {
			memprintf(err, "'%s' expects <type> to either be 'path' or 'cpath'", args[0]);
			goto err;
		}
		type = args[2];
	}

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		memprintf(err, "memory allocation failed");
		goto err;
	}
	p->path = strdup(path);
	if (p->path == NULL) {
		memprintf(err, "memory allocation failed");
		goto err2;
	}
	p->type = strdup(type);
	if (p->type == NULL) {
		memprintf(err, "memory allocation failed");
		goto err2;
	}
	LIST_APPEND(&prepend_path_list, &p->l);

	/* Handle the global state and the per-thread state for the first
	 * thread. The remaining threads will be initialized based on
	 * prepend_path_list.
	 */
	for (i = 0; i < 2; i++) {
		lua_State *L = hlua_states[i];
		const char *error;

		if (setjmp(safe_ljmp_env) != 0) {
			lua_atpanic(L, hlua_panic_safe);
			if (lua_type(L, -1) == LUA_TSTRING)
				error = hlua_tostring_safe(L, -1);
			else
				error = "critical error";
			fprintf(stderr, "lua-prepend-path: %s.\n", error);
			exit(1);
		} else {
			lua_atpanic(L, hlua_panic_ljmp);
		}

		hlua_prepend_path(L, type, path);

		lua_atpanic(L, hlua_panic_safe);
	}

	return 0;

err2:
	free(p->type);
	free(p->path);
err:
	free(p);
	return -1;
}

/* configuration keywords declaration */
static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "lua-prepend-path",         hlua_config_prepend_path },
	{ CFG_GLOBAL, "lua-load",                 hlua_load },
	{ CFG_GLOBAL, "lua-load-per-thread",      hlua_load_per_thread },
	{ CFG_GLOBAL, "tune.lua.session-timeout", hlua_session_timeout },
	{ CFG_GLOBAL, "tune.lua.task-timeout",    hlua_task_timeout },
	{ CFG_GLOBAL, "tune.lua.service-timeout", hlua_applet_timeout },
	{ CFG_GLOBAL, "tune.lua.burst-timeout",   hlua_burst_timeout },
	{ CFG_GLOBAL, "tune.lua.forced-yield",    hlua_forced_yield },
	{ CFG_GLOBAL, "tune.lua.maxmem",          hlua_parse_maxmem },
	{ CFG_GLOBAL, "tune.lua.log.loggers",     hlua_cfg_parse_log_loggers },
	{ CFG_GLOBAL, "tune.lua.log.stderr",      hlua_cfg_parse_log_stderr },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

#ifdef USE_OPENSSL

/*
 * This function replace a ckch_store by another one, and rebuild the ckch_inst and all its dependencies.
 * It does the sam as "cli_io_handler_commit_cert" but for lua, the major
 * difference is that the yield in lua and for the CLI is not handled the same
 * way.
 */
__LJMP static int hlua_ckch_commit_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct ckch_inst **lua_ckchi = lua_touserdata(L, -1);
	struct ckch_store **lua_ckchs = lua_touserdata(L, -2);
	struct ckch_inst *ckchi = *lua_ckchi;
	struct ckch_store *old_ckchs = lua_ckchs[0];
	struct ckch_store *new_ckchs = lua_ckchs[1];
	struct hlua *hlua;
	char *err = NULL;
	int y = 1;

	hlua = hlua_gethlua(L);

	/* get the first ckchi to copy */
	if (ckchi == NULL)
		ckchi = LIST_ELEM(old_ckchs->ckch_inst.n, typeof(ckchi), by_ckchs);

	/* walk through the old ckch_inst and creates new ckch_inst using the updated ckchs */
	list_for_each_entry_from(ckchi, &old_ckchs->ckch_inst, by_ckchs) {
		struct ckch_inst *new_inst;

		/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances
		 * during runtime
		 */
		if (hlua && (y % 10) == 0) {

			*lua_ckchi = ckchi;

			task_wakeup(hlua->task, TASK_WOKEN_MSG);
			MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_ckch_commit_yield, TICK_ETERNITY, 0));
		}

		if (ckch_inst_rebuild(new_ckchs, ckchi, &new_inst, &err))
			goto error;

		/* link the new ckch_inst to the duplicate */
		LIST_APPEND(&new_ckchs->ckch_inst, &new_inst->by_ckchs);
		y++;
	}

	/* The generation is finished, we can insert everything */
	ckch_store_replace(old_ckchs, new_ckchs);

	lua_pop(L, 2); /* pop the lua_ckchs and ckchi */

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	return 0;

error:
	ckch_store_free(new_ckchs);
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	hlua_pushfstring_safe(L, "%s", err);
	free(err);
	WILL_LJMP(lua_error(L));

	return 0;
}

/*
 * Replace a ckch_store <filename> in the ckchs_tree with a ckch_store created
 * from the table in parameter.
 *
 * This is equivalent to  "set ssl cert" + "commit ssl cert" over the CLI, which
 * means it does not need to have a transaction since everything is done in the
 * same function.
 *
 * CertCache.set{filename="", crt="", key="", sctl="", ocsp="", issuer=""}
 *
 */
__LJMP static int hlua_ckch_set(lua_State *L)
{
	struct hlua *hlua;
	struct ckch_inst **lua_ckchi;
	struct ckch_store **lua_ckchs;
	struct ckch_store *old_ckchs = NULL;
	struct ckch_store *new_ckchs = NULL;
	int errcode = 0;
	char *err = NULL;
	struct cert_exts *cert_ext = NULL;
	char *filename;
	struct ckch_data *data;
	int ret;

	if (lua_type(L, -1) != LUA_TTABLE)
		WILL_LJMP(luaL_error(L, "'CertCache.set' needs a table as argument"));

	hlua = hlua_gethlua(L);
	if (hlua && HLUA_CANT_YIELD(hlua)) {
		/* using hlua_ckch_set() during runtime from a context that
		 * doesn't allow yielding (e.g.: fetches) is not supported
		 * as it may cause contention.
		 */
		WILL_LJMP(luaL_error(L, "Cannot use CertCache.set from a "
		                        "non-yield capable runtime context"));
	}

	/* FIXME: this should not return an error but should come back later */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		WILL_LJMP(luaL_error(L, "CertCache already under lock"));

	ret = lua_getfield(L, -1, "filename");
	if (ret != LUA_TSTRING) {
		memprintf(&err, "%sNo filename specified!", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}
	filename = (char *)lua_tostring(L, -1);


	/* look for the filename in the tree */
	old_ckchs = ckchs_lookup(filename);
	if (!old_ckchs) {
		memprintf(&err, "%sCan't replace a certificate which is not referenced by the configuration!", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}
	/* TODO: handle extra_files_noext */

	new_ckchs = ckchs_dup(old_ckchs);
	if (!new_ckchs) {
		memprintf(&err, "%sCannot allocate memory!", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	data = new_ckchs->data;

	/* loop on the field in the table, which have the same name as the
	 * possible extensions of files */
	lua_pushnil(L);
	while (lua_next(L, 1)) {
		int i;
		const char *field = lua_tostring(L, -2);
		char *payload = (char *)lua_tostring(L, -1);

		if (!field || strcmp(field, "filename") == 0) {
			lua_pop(L, 1);
			continue;
		}

		for (i = 0; field && cert_exts[i].ext != NULL; i++) {
			if (strcmp(field, cert_exts[i].ext) == 0) {
				cert_ext = &cert_exts[i];
				break;
			}
		}

		/* this is the default type, the field is not supported */
		if (cert_ext == NULL) {
			memprintf(&err, "%sUnsupported field '%s'", err ? err : "", field);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}

		/* Reset the OCSP CID */
		if (cert_ext->type == CERT_TYPE_PEM || cert_ext->type == CERT_TYPE_KEY ||
		    cert_ext->type == CERT_TYPE_ISSUER) {
			OCSP_CERTID_free(new_ckchs->data->ocsp_cid);
			new_ckchs->data->ocsp_cid = NULL;
		}

		/* apply the change on the duplicate */
		if (cert_ext->load(filename, payload, data, &err) != 0) {
			memprintf(&err, "%sCan't load the payload for '%s'", err ? err : "", cert_ext->ext);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		lua_pop(L, 1);
	}

	/* store the pointers on the lua stack */
        lua_ckchs = lua_newuserdata(L, sizeof(struct ckch_store *) * 2);
	lua_ckchs[0] = old_ckchs;
	lua_ckchs[1] = new_ckchs;
	lua_ckchi = lua_newuserdata(L, sizeof(struct ckch_inst *));
	*lua_ckchi = NULL;

	if (hlua) {
		/* yield right away to let hlua_ckch_commit_yield() benefit from
		 * a fresh task cycle on next wakeup
		 */
		task_wakeup(hlua->task, TASK_WOKEN_MSG);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_ckch_commit_yield, TICK_ETERNITY, 0));
	} else {
		/* body/init context: yielding not available, perform the commit as a
		 * 1-shot operation (may be slow, but haproxy process is starting so
		 * it is acceptable)
		 */
		hlua_ckch_commit_yield(L, LUA_OK, 0);
	}

end:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	if (errcode & ERR_CODE) {
		ckch_store_free(new_ckchs);
		hlua_pushfstring_safe(L, "%s", err);
		free(err);
		WILL_LJMP(lua_error(L));
	}
	free(err);

	return 0;
}

#else

__LJMP static int hlua_ckch_set(lua_State *L)
{
	WILL_LJMP(luaL_error(L, "'CertCache.set' needs an HAProxy built with OpenSSL"));

	return 0;
}
#endif /* ! USE_OPENSSL */



/* This function can fail with an abort() due to an Lua critical error.
 * We are in the initialisation process of HAProxy, this abort() is
 * tolerated.
 */
int hlua_post_init_state(lua_State *L)
{
	struct hlua_init_function *init;
	const char *msg;
	enum hlua_exec ret;
	const char *error;
	const char *kind;
	const char *trace;
	int return_status = 1;
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
	int nres;
#endif

	/* disable memory limit checks if limit is not set */
	if (!hlua_global_allocator.limit)
		hlua_global_allocator.limit = ~hlua_global_allocator.limit;

	/* Call post initialisation function in safe environment. */
	if (setjmp(safe_ljmp_env) != 0) {
		lua_atpanic(L, hlua_panic_safe);
		if (lua_type(L, -1) == LUA_TSTRING)
			error = hlua_tostring_safe(L, -1);
		else
			error = "critical error";
		fprintf(stderr, "Lua post-init: %s.\n", error);
		exit(1);
	} else {
		lua_atpanic(L, hlua_panic_ljmp);
	}

	list_for_each_entry(init, &hlua_init_functions[hlua_state_id], l) {
		hlua_pushref(L, init->function_ref);
		/* function ref should be released right away since it was pushed
		 * on the stack and will not be used anymore
		 */
		hlua_unref(L, init->function_ref);

#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
		ret = lua_resume(L, NULL, 0, &nres);
#else
		ret = lua_resume(L, NULL, 0);
#endif
		kind = NULL;
		switch (ret) {

		case LUA_OK:
			lua_pop(L, -1);
			break;

		case LUA_ERRERR:
			kind = "message handler error";
			__fallthrough;
		case LUA_ERRRUN:
			if (!kind)
				kind = "runtime error";
			msg = hlua_tostring_safe(L, -1);
			trace = hlua_traceback(L, ", ");
			if (msg)
				ha_alert("Lua init: %s: '%s' from %s\n", kind, msg, trace);
			else
				ha_alert("Lua init: unknown %s from %s\n", kind, trace);

			lua_settop(L, 0); /* Empty the stack. */
			return_status = 0;
			break;

		default:
			/* Unknown error */
			kind = "Unknown error";
			__fallthrough;
		case LUA_YIELD:
			/* yield is not configured at this step, this state doesn't happen */
			if (!kind)
				kind = "yield not allowed";
			__fallthrough;
		case LUA_ERRMEM:
			if (!kind)
				kind = "out of memory error";
			lua_settop(L, 0); /* Empty the stack. */
			trace = hlua_traceback(L, ", ");
			ha_alert("Lua init: %s: %s\n", kind, trace);
			return_status = 0;
			break;
		}
		if (!return_status)
			break;
	}

	lua_atpanic(L, hlua_panic_safe);
	return return_status;
}

int hlua_post_init()
{
	int ret;
	int i;
	int errors;
	char *err = NULL;
	struct hlua_function *fcn;
	struct hlua_reg_filter *reg_flt;

#if defined(USE_OPENSSL)
	/* Initialize SSL server. */
	if (socket_ssl->xprt->prepare_srv) {
		int saved_used_backed = global.ssl_used_backend;
		// don't affect maxconn automatic computation
		socket_ssl->xprt->prepare_srv(socket_ssl);
		global.ssl_used_backend = saved_used_backed;
	}
#endif

	/* Perform post init of common thread */
	hlua_state_id = 0;
	ha_set_thread(&ha_thread_info[0]);
	ret = hlua_post_init_state(hlua_states[hlua_state_id]);
	if (ret == 0)
		return 0;

	/* init remaining lua states and load files */
	for (hlua_state_id = 2; hlua_state_id < global.nbthread + 1; hlua_state_id++) {

		/* set thread context */
		ha_set_thread(&ha_thread_info[hlua_state_id - 1]);

		/* Init lua state */
		hlua_states[hlua_state_id] = hlua_init_state(hlua_state_id);

		/* Load lua files */
		for (i = 0; per_thread_load && per_thread_load[i]; i++) {
			ret = hlua_load_state(per_thread_load[i], hlua_states[hlua_state_id], &err);
			if (ret != 0) {
				ha_alert("Lua init: %s\n", err);
				return 0;
			}
		}
	}

	/* Reset thread context */
	ha_set_thread(NULL);

	/* Execute post init for all states */
	for (hlua_state_id = 1; hlua_state_id < global.nbthread + 1; hlua_state_id++) {

		/* set thread context */
		ha_set_thread(&ha_thread_info[hlua_state_id - 1]);

		/* run post init */
		ret = hlua_post_init_state(hlua_states[hlua_state_id]);
		if (ret == 0)
			return 0;
	}

	/* Reset thread context */
	ha_set_thread(NULL);

	/* control functions registering. Each function must have:
	 *  - only the function_ref[0] set positive and all other to -1
	 *  - only the function_ref[0] set to -1 and all other positive
	 * This ensure a same reference is not used both in shared
	 * lua state and thread dedicated lua state. Note: is the case
	 * reach, the shared state is priority, but the bug will be
	 * complicated to found for the end user.
	 */
	errors = 0;
	list_for_each_entry(fcn, &referenced_functions, l) {
		ret = 0;
		for (i = 1; i < global.nbthread + 1; i++) {
			if (fcn->function_ref[i] == -1)
				ret--;
			else
				ret++;
		}
		if (abs(ret) != global.nbthread) {
			ha_alert("Lua function '%s' is not referenced in all thread. "
			         "Expect function in all thread or in none thread.\n", fcn->name);
			errors++;
			continue;
		}

		if ((fcn->function_ref[0] == -1) == (ret < 0)) {
			ha_alert("Lua function '%s' is referenced both ins shared Lua context (through lua-load) "
			         "and per-thread Lua context (through lua-load-per-thread). these two context "
			         "exclusive.\n", fcn->name);
			errors++;
		}
	}

	/* Do the same with registered filters */
	list_for_each_entry(reg_flt, &referenced_filters, l) {
		ret = 0;
		for (i = 1; i < global.nbthread + 1; i++) {
			if (reg_flt->flt_ref[i] == -1)
				ret--;
			else
				ret++;
		}
		if (abs(ret) != global.nbthread) {
			ha_alert("Lua filter '%s' is not referenced in all thread. "
			         "Expect function in all thread or in none thread.\n", reg_flt->name);
			errors++;
			continue;
		}

		if ((reg_flt->flt_ref[0] == -1) == (ret < 0)) {
			ha_alert("Lua filter '%s' is referenced both ins shared Lua context (through lua-load) "
			         "and per-thread Lua context (through lua-load-per-thread). these two context "
			         "exclusive.\n", reg_flt->name);
			errors++;
		}
	}


	if (errors > 0)
		return 0;

	/* after this point, this global will no longer be used, so set to
	 * -1 in order to have probably a segfault if someone use it
	 */
	hlua_state_id = -1;

	return 1;
}

/* The memory allocator used by the Lua stack. <ud> is a pointer to the
 * allocator's context. <ptr> is the pointer to alloc/free/realloc. <osize>
 * is the previously allocated size or the kind of object in case of a new
 * allocation. <nsize> is the requested new size. A new allocation is
 * indicated by <ptr> being NULL. A free is indicated by <nsize> being
 * zero. This one verifies that the limits are respected but is optimized
 * for the fast case where limits are not used, hence stats are not updated.
 *
 * Warning: while this API ressembles glibc's realloc() a lot, glibc surpasses
 * POSIX by making realloc(ptr,0) an effective free(), but others do not do
 * that and will simply allocate zero as if it were the result of malloc(0),
 * so mapping this onto realloc() will lead to memory leaks on non-glibc
 * systems.
 */
static void *hlua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct hlua_mem_allocator *zone = ud;
	size_t limit, old, new;

	/* a limit of ~0 means unlimited and boot complete, so there's no need
	 * for accounting anymore.
	 */
	if (likely(~zone->limit == 0)) {
		if (!nsize)
			ha_free(&ptr);
		else
			ptr = realloc(ptr, nsize);
		return ptr;
	}

	if (!ptr)
		osize = 0;

	/* enforce strict limits across all threads */
	limit = zone->limit;
	old = _HA_ATOMIC_LOAD(&zone->allocated);
	do {
		new = old + nsize - osize;
		if (unlikely(nsize && limit && new > limit))
			return NULL;
	} while (!_HA_ATOMIC_CAS(&zone->allocated, &old, new));

	if (!nsize)
		ha_free(&ptr);
	else
		ptr = realloc(ptr, nsize);

	if (unlikely(!ptr && nsize)) // failed
		_HA_ATOMIC_SUB(&zone->allocated, nsize - osize);

	__ha_barrier_atomic_store();
	return ptr;
}

/* This function can fail with an abort() due to a Lua critical error.
 * We are in the initialisation process of HAProxy, this abort() is
 * tolerated.
 */
lua_State *hlua_init_state(int thread_num)
{
	int i;
	int idx;
	struct sample_fetch *sf;
	struct sample_conv *sc;
	char *p;
	const char *error_msg;
	void **context;
	lua_State *L;
	struct prepend_path *pp;

	/* Init main lua stack. */
	L = lua_newstate(hlua_alloc, &hlua_global_allocator);

	if (!L) {
		fprintf(stderr,
		        "Lua init: critical error: lua_newstate() returned NULL."
		        " This may possibly be caused by a memory allocation error.\n");
		exit(1);
	}

	/* Initialise Lua context to NULL */
	context = lua_getextraspace(L);
	*context = NULL;

	/* From this point, until the end of the initialisation function,
	 * the Lua function can fail with an abort. We are in the initialisation
	 * process of HAProxy, this abort() is tolerated.
	 */

	/* Call post initialisation function in safe environment. */
	if (setjmp(safe_ljmp_env) != 0) {
		lua_atpanic(L, hlua_panic_safe);
		if (lua_type(L, -1) == LUA_TSTRING)
			error_msg = hlua_tostring_safe(L, -1);
		else
			error_msg = "critical error";
		fprintf(stderr, "Lua init: %s.\n", error_msg);
		exit(1);
	} else {
		lua_atpanic(L, hlua_panic_ljmp);
	}

	/* Initialise lua. */
	luaL_openlibs(L);
#define HLUA_PREPEND_PATH_TOSTRING1(x) #x
#define HLUA_PREPEND_PATH_TOSTRING(x) HLUA_PREPEND_PATH_TOSTRING1(x)
#ifdef HLUA_PREPEND_PATH
	hlua_prepend_path(L, "path", HLUA_PREPEND_PATH_TOSTRING(HLUA_PREPEND_PATH));
#endif
#ifdef HLUA_PREPEND_CPATH
	hlua_prepend_path(L, "cpath", HLUA_PREPEND_PATH_TOSTRING(HLUA_PREPEND_CPATH));
#endif
#undef HLUA_PREPEND_PATH_TOSTRING
#undef HLUA_PREPEND_PATH_TOSTRING1

	/* Apply configured prepend path */
	list_for_each_entry(pp, &prepend_path_list, l)
		hlua_prepend_path(L, pp->type, pp->path);

	/*
	 * Override some lua functions.
	 *
	 */

	/* push our "safe" coroutine.create() function */
	lua_getglobal(L, "coroutine");
	lua_pushcclosure(L, hlua_coroutine_create, 0);
	lua_setfield(L, -2, "create");

	/*
	 *
	 * Create "core" object.
	 *
	 */

	/* This table entry is the object "core" base. */
	lua_newtable(L);

	/* set the thread id */
	hlua_class_const_int(L, "thread", thread_num);

	/* Push the loglevel constants. */
		hlua_class_const_int(L, "silent", -1);
	for (i = 0; i < NB_LOG_LEVELS; i++)
		hlua_class_const_int(L, log_levels[i], i);

	/* Register special functions. */
	hlua_class_function(L, "register_init", hlua_register_init);
	hlua_class_function(L, "register_task", hlua_register_task);
	hlua_class_function(L, "register_fetches", hlua_register_fetches);
	hlua_class_function(L, "register_converters", hlua_register_converters);
	hlua_class_function(L, "register_action", hlua_register_action);
	hlua_class_function(L, "register_service", hlua_register_service);
	hlua_class_function(L, "register_cli", hlua_register_cli);
	hlua_class_function(L, "register_filter", hlua_register_filter);
	hlua_class_function(L, "yield", hlua_yield);
	hlua_class_function(L, "set_nice", hlua_set_nice);
	hlua_class_function(L, "sleep", hlua_sleep);
	hlua_class_function(L, "msleep", hlua_msleep);
	hlua_class_function(L, "add_acl", hlua_add_acl);
	hlua_class_function(L, "del_acl", hlua_del_acl);
	hlua_class_function(L, "set_map", hlua_set_map);
	hlua_class_function(L, "del_map", hlua_del_map);
	hlua_class_function(L, "get_var", hlua_core_get_var);
	hlua_class_function(L, "tcp", hlua_socket_new);
	hlua_class_function(L, "httpclient", hlua_httpclient_new);
	hlua_class_function(L, "event_sub", hlua_event_global_sub);
	hlua_class_function(L, "log", hlua_log);
	hlua_class_function(L, "Debug", hlua_log_debug);
	hlua_class_function(L, "Info", hlua_log_info);
	hlua_class_function(L, "Warning", hlua_log_warning);
	hlua_class_function(L, "Alert", hlua_log_alert);
	hlua_class_function(L, "done", hlua_done);
	hlua_class_function(L, "disable_legacy_mailers", hlua_disable_legacy_mailers);
	hlua_fcn_reg_core_fcn(L);

	lua_setglobal(L, "core");

	/*
	 *
	 * Create "act" object.
	 *
	 */

	/* This table entry is the object "act" base. */
	lua_newtable(L);

	/* push action return constants */
	hlua_class_const_int(L, "CONTINUE", ACT_RET_CONT);
	hlua_class_const_int(L, "STOP",     ACT_RET_STOP);
	hlua_class_const_int(L, "YIELD",    ACT_RET_YIELD);
	hlua_class_const_int(L, "ERROR",    ACT_RET_ERR);
	hlua_class_const_int(L, "DONE",     ACT_RET_DONE);
	hlua_class_const_int(L, "DENY",     ACT_RET_DENY);
	hlua_class_const_int(L, "ABORT",    ACT_RET_ABRT);
	hlua_class_const_int(L, "INVALID",  ACT_RET_INV);

	hlua_class_function(L, "wake_time", hlua_set_wake_time);

	lua_setglobal(L, "act");

	/*
	 *
	 * Create "Filter" object.
	 *
	 */

	/* This table entry is the object "filter" base. */
	lua_newtable(L);

	/* push flags and constants */
	hlua_class_const_int(L, "CONTINUE", 1);
	hlua_class_const_int(L, "WAIT",     0);
	hlua_class_const_int(L, "ERROR",    -1);

	hlua_class_const_int(L, "FLT_CFG_FL_HTX", FLT_CFG_FL_HTX);

	hlua_class_function(L, "wake_time", hlua_set_wake_time);
	hlua_class_function(L, "register_data_filter", hlua_register_data_filter);
	hlua_class_function(L, "unregister_data_filter", hlua_unregister_data_filter);

	lua_setglobal(L, "filter");

	/*
	 *
	 * Register class Map
	 *
	 */

	/* This table entry is the object "Map" base. */
	lua_newtable(L);

	/* register pattern types. */
	for (i=0; i<PAT_MATCH_NUM; i++)
		hlua_class_const_int(L, pat_match_names[i], i);
	for (i=0; i<PAT_MATCH_NUM; i++) {
		snprintf(trash.area, trash.size, "_%s", pat_match_names[i]);
		hlua_class_const_int(L, trash.area, i);
	}

	/* register constructor. */
	hlua_class_function(L, "new", hlua_map_new);

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register . */
	hlua_class_function(L, "lookup", hlua_map_lookup);
	hlua_class_function(L, "slookup", hlua_map_slookup);

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry.
	 * The function hlua_register_metatable() pops the stack, so we
	 * previously create a copy of the table.
	 */
	lua_pushvalue(L, -1); /* Copy the -1 entry and push it on the stack. */
	class_map_ref = hlua_register_metatable(L, CLASS_MAP);

	/* Assign the metatable to the mai Map object. */
	lua_setmetatable(L, -2);

	/* Set a name to the table. */
	lua_setglobal(L, "Map");

	/*
	 *
	 * Register "CertCache" class
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);
	/* Register */
	hlua_class_function(L, "set",         hlua_ckch_set);
	lua_setglobal(L, CLASS_CERTCACHE); /* Create global object called CertCache */

	/*
	 *
	 * Register class Channel
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register . */
	hlua_class_function(L, "data",        hlua_channel_get_data);
	hlua_class_function(L, "line",        hlua_channel_get_line);
	hlua_class_function(L, "set",         hlua_channel_set_data);
	hlua_class_function(L, "remove",      hlua_channel_del_data);
	hlua_class_function(L, "append",      hlua_channel_append);
	hlua_class_function(L, "prepend",     hlua_channel_prepend);
	hlua_class_function(L, "insert",      hlua_channel_insert_data);
	hlua_class_function(L, "send",        hlua_channel_send);
	hlua_class_function(L, "forward",     hlua_channel_forward);
	hlua_class_function(L, "input",       hlua_channel_get_in_len);
	hlua_class_function(L, "output",      hlua_channel_get_out_len);
	hlua_class_function(L, "may_recv",    hlua_channel_may_recv);
	hlua_class_function(L, "is_full",     hlua_channel_is_full);
	hlua_class_function(L, "is_resp",     hlua_channel_is_resp);

	/* Deprecated API */
	hlua_class_function(L, "get",         hlua_channel_get);
	hlua_class_function(L, "dup",         hlua_channel_dup);
	hlua_class_function(L, "getline",     hlua_channel_getline);
	hlua_class_function(L, "get_in_len",  hlua_channel_get_in_len);
	hlua_class_function(L, "get_out_len", hlua_channel_get_out_len);

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_channel_ref = hlua_register_metatable(L, CLASS_CHANNEL);

	/*
	 *
	 * Register class Fetches
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Browse existing fetches and create the associated
	 * object method.
	 */
	sf = NULL;
	while ((sf = sample_fetch_getnext(sf, &idx)) != NULL) {
		/* gL.Tua doesn't support '.' and '-' in the function names, replace it
		 * by an underscore.
		 */
		strlcpy2(trash.area, sf->kw, trash.size);
		for (p = trash.area; *p; p++)
			if (*p == '.' || *p == '-' || *p == '+')
				*p = '_';

		/* Register the function. */
		lua_pushstring(L, trash.area);
		lua_pushlightuserdata(L, sf);
		lua_pushcclosure(L, hlua_run_sample_fetch, 1);
		lua_rawset(L, -3);
	}

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_fetches_ref = hlua_register_metatable(L, CLASS_FETCHES);

	/*
	 *
	 * Register class Converters
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Browse existing converters and create the associated
	 * object method.
	 */
	sc = NULL;
	while ((sc = sample_conv_getnext(sc, &idx)) != NULL) {
		/* gL.Tua doesn't support '.' and '-' in the function names, replace it
		 * by an underscore.
		 */
		strlcpy2(trash.area, sc->kw, trash.size);
		for (p = trash.area; *p; p++)
			if (*p == '.' || *p == '-' || *p == '+')
				*p = '_';

		/* Register the function. */
		lua_pushstring(L, trash.area);
		lua_pushlightuserdata(L, sc);
		lua_pushcclosure(L, hlua_run_sample_conv, 1);
		lua_rawset(L, -3);
	}

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_converters_ref = hlua_register_metatable(L, CLASS_CONVERTERS);

	/*
	 *
	 * Register class HTTP
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register Lua functions. */
	hlua_class_function(L, "req_get_headers",hlua_http_req_get_headers);
	hlua_class_function(L, "req_del_header", hlua_http_req_del_hdr);
	hlua_class_function(L, "req_rep_header", hlua_http_req_rep_hdr);
	hlua_class_function(L, "req_rep_value",  hlua_http_req_rep_val);
	hlua_class_function(L, "req_add_header", hlua_http_req_add_hdr);
	hlua_class_function(L, "req_set_header", hlua_http_req_set_hdr);
	hlua_class_function(L, "req_set_method", hlua_http_req_set_meth);
	hlua_class_function(L, "req_set_path",   hlua_http_req_set_path);
	hlua_class_function(L, "req_set_query",  hlua_http_req_set_query);
	hlua_class_function(L, "req_set_uri",    hlua_http_req_set_uri);

	hlua_class_function(L, "res_get_headers",hlua_http_res_get_headers);
	hlua_class_function(L, "res_del_header", hlua_http_res_del_hdr);
	hlua_class_function(L, "res_rep_header", hlua_http_res_rep_hdr);
	hlua_class_function(L, "res_rep_value",  hlua_http_res_rep_val);
	hlua_class_function(L, "res_add_header", hlua_http_res_add_hdr);
	hlua_class_function(L, "res_set_header", hlua_http_res_set_hdr);
	hlua_class_function(L, "res_set_status", hlua_http_res_set_status);

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_http_ref = hlua_register_metatable(L, CLASS_HTTP);

	/*
	 *
	 * Register class HTTPMessage
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register Lua functions. */
	hlua_class_function(L, "is_resp",     hlua_http_msg_is_resp);
	hlua_class_function(L, "get_stline",  hlua_http_msg_get_stline);
	hlua_class_function(L, "get_headers", hlua_http_msg_get_headers);
	hlua_class_function(L, "del_header",  hlua_http_msg_del_hdr);
	hlua_class_function(L, "rep_header",  hlua_http_msg_rep_hdr);
	hlua_class_function(L, "rep_value",   hlua_http_msg_rep_val);
	hlua_class_function(L, "add_header",  hlua_http_msg_add_hdr);
	hlua_class_function(L, "set_header",  hlua_http_msg_set_hdr);
	hlua_class_function(L, "set_method",  hlua_http_msg_set_meth);
	hlua_class_function(L, "set_path",    hlua_http_msg_set_path);
	hlua_class_function(L, "set_query",   hlua_http_msg_set_query);
	hlua_class_function(L, "set_uri",     hlua_http_msg_set_uri);
	hlua_class_function(L, "set_status",  hlua_http_msg_set_status);
	hlua_class_function(L, "is_full",     hlua_http_msg_is_full);
	hlua_class_function(L, "may_recv",    hlua_http_msg_may_recv);
	hlua_class_function(L, "eom",         hlua_http_msg_is_eom);
	hlua_class_function(L, "input",       hlua_http_msg_get_in_len);
	hlua_class_function(L, "output",      hlua_http_msg_get_out_len);

	hlua_class_function(L, "body",        hlua_http_msg_get_body);
	hlua_class_function(L, "set",         hlua_http_msg_set_data);
	hlua_class_function(L, "remove",      hlua_http_msg_del_data);
	hlua_class_function(L, "append",      hlua_http_msg_append);
	hlua_class_function(L, "prepend",     hlua_http_msg_prepend);
	hlua_class_function(L, "insert",      hlua_http_msg_insert_data);
	hlua_class_function(L, "set_eom",     hlua_http_msg_set_eom);
	hlua_class_function(L, "unset_eom",   hlua_http_msg_unset_eom);

	hlua_class_function(L, "send",        hlua_http_msg_send);
	hlua_class_function(L, "forward",     hlua_http_msg_forward);

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_http_msg_ref = hlua_register_metatable(L, CLASS_HTTP_MSG);

	/*
	 *
	 * Register class HTTPClient
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "get",         hlua_httpclient_get);
	hlua_class_function(L, "head",        hlua_httpclient_head);
	hlua_class_function(L, "put",         hlua_httpclient_put);
	hlua_class_function(L, "post",        hlua_httpclient_post);
	hlua_class_function(L, "delete",      hlua_httpclient_delete);
	lua_settable(L, -3); /* Sets the __index entry. */
	/* Register the garbage collector entry. */
	lua_pushstring(L, "__gc");
	lua_pushcclosure(L, hlua_httpclient_gc, 0);
	lua_settable(L, -3); /* Push the last 2 entries in the table at index -3 */



	class_httpclient_ref = hlua_register_metatable(L, CLASS_HTTPCLIENT);
	/*
	 *
	 * Register class AppletTCP
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register Lua functions. */
	hlua_class_function(L, "getline",   hlua_applet_tcp_getline);
	hlua_class_function(L, "receive",   hlua_applet_tcp_recv);
	hlua_class_function(L, "send",      hlua_applet_tcp_send);
	hlua_class_function(L, "set_priv",  hlua_applet_tcp_set_priv);
	hlua_class_function(L, "get_priv",  hlua_applet_tcp_get_priv);
	hlua_class_function(L, "set_var",   hlua_applet_tcp_set_var);
	hlua_class_function(L, "unset_var", hlua_applet_tcp_unset_var);
	hlua_class_function(L, "get_var",   hlua_applet_tcp_get_var);

	lua_settable(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_applet_tcp_ref = hlua_register_metatable(L, CLASS_APPLET_TCP);

	/*
	 *
	 * Register class AppletHTTP
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register Lua functions. */
	hlua_class_function(L, "set_priv",       hlua_applet_http_set_priv);
	hlua_class_function(L, "get_priv",       hlua_applet_http_get_priv);
	hlua_class_function(L, "set_var",        hlua_applet_http_set_var);
	hlua_class_function(L, "unset_var",      hlua_applet_http_unset_var);
	hlua_class_function(L, "get_var",        hlua_applet_http_get_var);
	hlua_class_function(L, "getline",        hlua_applet_http_getline);
	hlua_class_function(L, "receive",        hlua_applet_http_recv);
	hlua_class_function(L, "send",           hlua_applet_http_send);
	hlua_class_function(L, "add_header",     hlua_applet_http_addheader);
	hlua_class_function(L, "set_status",     hlua_applet_http_status);
	hlua_class_function(L, "start_response", hlua_applet_http_start_response);

	lua_settable(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_applet_http_ref = hlua_register_metatable(L, CLASS_APPLET_HTTP);

	/*
	 *
	 * Register class TXN
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register Lua functions. */
	hlua_class_function(L, "set_priv",            hlua_set_priv);
	hlua_class_function(L, "get_priv",            hlua_get_priv);
	hlua_class_function(L, "set_var",             hlua_set_var);
	hlua_class_function(L, "unset_var",           hlua_unset_var);
	hlua_class_function(L, "get_var",             hlua_get_var);
	hlua_class_function(L, "done",                hlua_txn_done);
	hlua_class_function(L, "reply",               hlua_txn_reply_new);
	hlua_class_function(L, "set_fc_mark",         hlua_txn_set_fc_mark);
	hlua_class_function(L, "set_fc_tos",          hlua_txn_set_fc_tos);
	hlua_class_function(L, "set_loglevel",        hlua_txn_set_loglevel);
	hlua_class_function(L, "set_mark",            hlua_txn_set_fc_mark); // DEPRECATED, use set_fc_mark
	hlua_class_function(L, "set_tos",             hlua_txn_set_fc_tos);  // DEPRECATED, use set_fc_tos
	hlua_class_function(L, "set_priority_class",  hlua_txn_set_priority_class);
	hlua_class_function(L, "set_priority_offset", hlua_txn_set_priority_offset);
	hlua_class_function(L, "deflog",              hlua_txn_deflog);
	hlua_class_function(L, "log",                 hlua_txn_log);
	hlua_class_function(L, "Debug",               hlua_txn_log_debug);
	hlua_class_function(L, "Info",                hlua_txn_log_info);
	hlua_class_function(L, "Warning",             hlua_txn_log_warning);
	hlua_class_function(L, "Alert",               hlua_txn_log_alert);

	lua_rawset(L, -3);

	/* Register previous table in the registry with reference and named entry. */
	class_txn_ref = hlua_register_metatable(L, CLASS_TXN);

	/*
	 *
	 * Register class reply
	 *
	 */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "set_status", hlua_txn_reply_set_status);
	hlua_class_function(L, "add_header", hlua_txn_reply_add_header);
	hlua_class_function(L, "del_header", hlua_txn_reply_del_header);
	hlua_class_function(L, "set_body",   hlua_txn_reply_set_body);
	lua_settable(L, -3); /* Sets the __index entry. */
	class_txn_reply_ref = luaL_ref(L, LUA_REGISTRYINDEX);


	/*
	 *
	 * Register class Socket
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

#ifdef USE_OPENSSL
	hlua_class_function(L, "connect_ssl", hlua_socket_connect_ssl);
#endif
	hlua_class_function(L, "connect",     hlua_socket_connect);
	hlua_class_function(L, "send",        hlua_socket_send);
	hlua_class_function(L, "receive",     hlua_socket_receive);
	hlua_class_function(L, "close",       hlua_socket_close);
	hlua_class_function(L, "getpeername", hlua_socket_getpeername);
	hlua_class_function(L, "getsockname", hlua_socket_getsockname);
	hlua_class_function(L, "setoption",   hlua_socket_setoption);
	hlua_class_function(L, "settimeout",  hlua_socket_settimeout);

	lua_rawset(L, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register the garbage collector entry. */
	lua_pushstring(L, "__gc");
	lua_pushcclosure(L, hlua_socket_gc, 0);
	lua_rawset(L, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register previous table in the registry with reference and named entry. */
	class_socket_ref = hlua_register_metatable(L, CLASS_SOCKET);

	lua_atpanic(L, hlua_panic_safe);

	return L;
}

void hlua_init(void) {
	int i;
	char *errmsg;
#ifdef USE_OPENSSL
	struct srv_kw *kw;
	int tmp_error;
	char *error;
	char *args[] = { /* SSL client configuration. */
		"ssl",
		"verify",
		"none",
		NULL
	};
#endif

	/* Init post init function list head */
	for (i = 0; i < MAX_THREADS + 1; i++)
		LIST_INIT(&hlua_init_functions[i]);

	/* Init state for common/shared lua parts */
	hlua_state_id = 0;
	ha_set_thread(NULL);
	hlua_states[0] = hlua_init_state(0);

	/* Init state 1 for thread 0. We have at least one thread. */
	hlua_state_id = 1;
	ha_set_thread(NULL);
	hlua_states[1] = hlua_init_state(1);

	/* Proxy and server configuration initialisation. */
	socket_proxy = alloc_new_proxy("LUA-SOCKET", PR_CAP_FE|PR_CAP_BE|PR_CAP_INT, &errmsg);
	if (!socket_proxy) {
		fprintf(stderr, "Lua init: %s\n", errmsg);
		exit(1);
	}

	/* Init TCP server: unchanged parameters */
	socket_tcp = new_server(socket_proxy);
	if (!socket_tcp) {
		fprintf(stderr, "Lua init: failed to allocate tcp server socket\n");
		exit(1);
	}

#ifdef USE_OPENSSL
	/* Init TCP server: unchanged parameters */
	socket_ssl = new_server(socket_proxy);
	if (!socket_ssl) {
		fprintf(stderr, "Lua init: failed to allocate ssl server socket\n");
		exit(1);
	}

	socket_ssl->use_ssl = 1;
	socket_ssl->xprt = xprt_get(XPRT_SSL);

	for (i = 0; args[i] != NULL; i++) {
		if ((kw = srv_find_kw(args[i])) != NULL) { /* Maybe it's registered server keyword */
			/*
			 *
			 * If the keyword is not known, we can search in the registered
			 * server keywords. This is useful to configure special SSL
			 * features like client certificates and ssl_verify.
			 *
			 */
			tmp_error = kw->parse(args, &i, socket_proxy, socket_ssl, &error);
			if (tmp_error != 0) {
				fprintf(stderr, "INTERNAL ERROR: %s\n", error);
				abort(); /* This must be never arrives because the command line
				            not editable by the user. */
			}
			i += kw->skip;
		}
	}
#endif

}

static void hlua_deinit()
{
	int thr;
	struct hlua_reg_filter *reg_flt, *reg_flt_bck;

	list_for_each_entry_safe(reg_flt, reg_flt_bck, &referenced_filters, l)
		release_hlua_reg_filter(reg_flt);

	for (thr = 0; thr < MAX_THREADS+1; thr++) {
		if (hlua_states[thr])
			lua_close(hlua_states[thr]);
	}

	srv_drop(socket_tcp);

#ifdef USE_OPENSSL
	srv_drop(socket_ssl);
#endif

	free_proxy(socket_proxy);
}

REGISTER_POST_DEINIT(hlua_deinit);

static void hlua_register_build_options(void)
{
	char *ptr = NULL;

	memprintf(&ptr, "Built with Lua version : %s", LUA_RELEASE);
	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, hlua_register_build_options);
