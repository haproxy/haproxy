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
#include <haproxy/connection.h>
#include <haproxy/h1.h>
#include <haproxy/hlua.h>
#include <haproxy/hlua_fcn.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_fetch.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/map.h>
#include <haproxy/obj_type.h>
#include <haproxy/pattern.h>
#include <haproxy/payload.h>
#include <haproxy/proxy-t.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/server-t.h>
#include <haproxy/session.h>
#include <haproxy/stats-t.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>
#include <haproxy/xref.h>


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
 *   §2.3); in particular, the error message is at the top of the
 *   stack. However, there is no guarantee about stack space. To push
 *   anything on the stack, the panic function must first check the
 *   available space (see §4.2).
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
static int hlua_panic_ljmp(lua_State *L) { WILL_LJMP(longjmp(safe_ljmp_env, 1)); }

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
static char **per_thread_load = NULL;

lua_State *hlua_init_state(int thread_id);

#define SET_SAFE_LJMP_L(__L, __HLUA) \
	({ \
		int ret; \
		if ((__HLUA)->state_id == 0) \
			HA_SPIN_LOCK(LUA_LOCK, &hlua_global_lock); \
		if (setjmp(safe_ljmp_env) != 0) { \
			lua_atpanic(__L, hlua_panic_safe); \
			ret = 0; \
			if ((__HLUA)->state_id == 0) \
				HA_SPIN_UNLOCK(LUA_LOCK, &hlua_global_lock); \
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
		if ((__HLUA)->state_id == 0) \
			HA_SPIN_UNLOCK(LUA_LOCK, &hlua_global_lock); \
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

/* This is the memory pool containing struct lua for applets
 * (including cli).
 */
DECLARE_STATIC_POOL(pool_head_hlua, "hlua", sizeof(struct hlua));

/* Used for Socket connection. */
static struct proxy socket_proxy;
static struct server socket_tcp;
#ifdef USE_OPENSSL
static struct server socket_ssl;
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
static int class_map_ref;
static int class_applet_tcp_ref;
static int class_applet_http_ref;
static int class_txn_reply_ref;

/* Global Lua execution timeout. By default Lua, execution linked
 * with stream (actions, sample-fetches and converters) have a
 * short timeout. Lua linked with tasks doesn't have a timeout
 * because a task may remain alive during all the haproxy execution.
 */
static unsigned int hlua_timeout_session = 4000; /* session timeout. */
static unsigned int hlua_timeout_task = TICK_ETERNITY; /* task timeout. */
static unsigned int hlua_timeout_applet = 4000; /* applet timeout. */

/* Interrupts the Lua processing each "hlua_nb_instruction" instructions.
 * it is used for preventing infinite loops.
 *
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
 *
 */
static unsigned int hlua_nb_instruction = 10000;

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

/* These functions converts types between HAProxy internal args or
 * sample and LUA types. Another function permits to check if the
 * LUA stack contains arguments according with an required ARG_T
 * format.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg);
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg);
__LJMP static int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                                     uint64_t mask, struct proxy *p);
static int hlua_smp2lua(lua_State *L, struct sample *smp);
static int hlua_smp2lua_str(lua_State *L, struct sample *smp);
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
	LIST_ADDQ(&referenced_functions, &fcn->l);
	for (i = 0; i < MAX_THREADS + 1; i++)
		fcn->function_ref[i] = -1;
	return fcn;
}

/* If the common state is set, the stack id is 0, otherwise it is the tid + 1 */
static inline int fcn_ref_to_stack_id(struct hlua_function *fcn)
{
	if (fcn->function_ref[0] == -1)
		return tid + 1;
	return 0;
}

/* Used to check an Lua function type in the stack. It creates and
 * returns a reference of the function. This function throws an
 * error if the rgument is not a "function".
 */
__LJMP unsigned int hlua_checkfunction(lua_State *L, int argno)
{
	if (!lua_isfunction(L, argno)) {
		const char *msg = lua_pushfstring(L, "function expected, got %s", luaL_typename(L, argno));
		WILL_LJMP(luaL_argerror(L, argno, msg));
	}
	lua_pushvalue(L, argno);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* Return the string that is of the top of the stack. */
const char *hlua_get_top_error_string(lua_State *L)
{
	if (lua_gettop(L) < 1)
		return "unknown error";
	if (lua_type(L, -1) != LUA_TSTRING)
		return "unknown error";
	return lua_tostring(L, -1);
}

__LJMP static const char *hlua_traceback(lua_State *L)
{
	lua_Debug ar;
	int level = 0;
	struct buffer *msg = get_trash_chunk();
	int filled = 0;

	while (lua_getstack(L, level++, &ar)) {

		/* Add separator */
		if (filled)
			chunk_appendf(msg, ", ");
		filled = 1;

		/* Fill fields:
		 * 'S': fills in the fields source, short_src, linedefined, lastlinedefined, and what;
		 * 'l': fills in the field currentline;
		 * 'n': fills in the field name and namewhat;
		 * 't': fills in the field istailcall;
		 */
		lua_getinfo(L, "Slnt", &ar);

		/* Append code localisation */
		if (ar.currentline > 0)
			chunk_appendf(msg, "%s:%d ", ar.short_src, ar.currentline);
		else
			chunk_appendf(msg, "%s ", ar.short_src);

		/*
		 * Get function name
		 *
		 * if namewhat is no empty, name is defined.
		 * what contains "Lua" for Lua function, "C" for C function,
		 * or "main" for main code.
		 */
		if (*ar.namewhat != '\0' && ar.name != NULL)  /* is there a name from code? */
			chunk_appendf(msg, "%s '%s'", ar.namewhat, ar.name);  /* use it */

		else if (*ar.what == 'm')  /* "main", the code is not executed in a function */
			chunk_appendf(msg, "main chunk");

		else if (*ar.what != 'C')  /* for Lua functions, use <file:line> */
			chunk_appendf(msg, "C function line %d", ar.linedefined);

		else  /* nothing left... */
			chunk_appendf(msg, "?");


		/* Display tailed call */
		if (ar.istailcall)
			chunk_appendf(msg, " ...");
	}

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
 */
static int hlua_pusherror(lua_State *L, const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	luaL_where(L, 1);
	lua_pushvfstring(L, fmt, argp);
	va_end(argp);
	lua_concat(L, 2);
	return 1;
}

/* This functions is used with sample fetch and converters. It
 * converts the HAProxy configuration argument in a lua stack
 * values.
 *
 * It takes an array of "arg", and each entry of the array is
 * converted and pushed in the LUA stack.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg)
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
static int hlua_smp2lua(lua_State *L, struct sample *smp)
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
static int hlua_smp2lua_str(lua_State *L, struct sample *smp)
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

/* the following functions are used to convert an Lua type in a
 * struct sample. This is useful to provide data from a converter
 * to the LUA code.
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
 * entries.
 */
__LJMP int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                              uint64_t mask, struct proxy *p)
{
	int min_arg;
	int i, idx;
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

		/* Check oversize. */
		if (idx >= ARGM_NBARGS && argp[idx].type != ARGT_STOP) {
			msg = "Malformed argument mask";
			goto error;
		}

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
					argp[idx].data.prx = p;
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
				msg = lua_pushfstring(L, "error compiling regex '%s' : '%s'",
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
				msg = lua_pushfstring(L, "unable to find userlist '%s'", argp[idx].data.str.area);
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
			msg = lua_pushfstring(L, "'%s' expected, got '%s'",
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
	for (i = 0; i < idx; i++) {
		if (argp[i].type == ARGT_STR)
			chunk_destroy(&argp[i].data.str);
		else if (argp[i].type == ARGT_REG)
			regex_free(argp[i].data.reg);
	}
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
static inline struct hlua *hlua_gethlua(lua_State *L)
{
	struct hlua **hlua = lua_getextraspace(L);
	return *hlua;
}
static inline void hlua_sethlua(struct hlua *hlua)
{
	struct hlua **hlua_store = lua_getextraspace(hlua->T);
	*hlua_store = hlua;
}

/* This function is used to send logs. It try to send on screen (stderr)
 * and on the default syslog server.
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

	send_log(px, level, "%s\n", trash.area);
	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
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
 */
__LJMP void hlua_yieldk(lua_State *L, int nresults, int ctx,
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
 * In some case (at least one), this function can be called from safe
 * environment, so we must not initialise it. While the support of
 * threads appear, the safe environment set a lock to ensure only one
 * Lua execution at a time. If we initialize safe environment in another
 * safe environment, we have a dead lock.
 *
 * set "already_safe" true if the context is initialized form safe
 * Lua function.
 *
 * This function manipulates two Lua stacks: the main and the thread. Only
 * the main stack can fail. The thread is not manipulated. This function
 * MUST NOT manipulate the created thread stack state, because it is not
 * protected against errors thrown by the thread stack.
 */
int hlua_ctx_init(struct hlua *lua, int state_id, struct task *task, int already_safe)
{
	lua->Mref = LUA_REFNIL;
	lua->flags = 0;
	lua->gc_count = 0;
	lua->wake_time = TICK_ETERNITY;
	lua->state_id = state_id;
	LIST_INIT(&lua->com);
	if (!already_safe) {
		if (!SET_SAFE_LJMP_PARENT(lua)) {
			lua->Tref = LUA_REFNIL;
			return 0;
		}
	}
	lua->T = lua_newthread(hlua_states[state_id]);
	if (!lua->T) {
		lua->Tref = LUA_REFNIL;
		if (!already_safe)
			RESET_SAFE_LJMP_PARENT(lua);
		return 0;
	}
	hlua_sethlua(lua);
	lua->Tref = luaL_ref(hlua_states[state_id], LUA_REGISTRYINDEX);
	lua->task = task;
	if (!already_safe)
		RESET_SAFE_LJMP_PARENT(lua);
	return 1;
}

/* Used to destroy the Lua coroutine when the attached stream or task
 * is destroyed. The destroy also the memory context. The struct "lua"
 * is not freed.
 */
void hlua_ctx_destroy(struct hlua *lua)
{
	if (!lua)
		return;

	if (!lua->T)
		goto end;

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

void hlua_hook(lua_State *L, lua_Debug *ar)
{
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return;

	/* Lua cannot yield when its returning from a function,
	 * so, we can fix the interrupt hook to 1 instruction,
	 * expecting that the function is finished.
	 */
	if (lua_gethookmask(L) & LUA_MASKRET) {
		lua_sethook(hlua->T, hlua_hook, LUA_MASKCOUNT, 1);
		return;
	}

	/* restore the interrupt condition. */
	lua_sethook(hlua->T, hlua_hook, LUA_MASKCOUNT, hlua_nb_instruction);

	/* If we interrupt the Lua processing in yieldable state, we yield.
	 * If the state is not yieldable, trying yield causes an error.
	 */
	if (lua_isyieldable(L))
		MAY_LJMP(hlua_yieldk(L, 0, 0, NULL, TICK_ETERNITY, HLUA_CTRLYIELD));

	/* If we cannot yield, update the clock and check the timeout. */
	tv_update_date(0, 1);
	hlua->run_time += now_ms - hlua->start_time;
	if (hlua->max_time && hlua->run_time >= hlua->max_time) {
		lua_pushfstring(L, "execution timeout");
		WILL_LJMP(lua_error(L));
	}

	/* Update the start time. */
	hlua->start_time = now_ms;

	/* Try to interrupt the process at the end of the current
	 * unyieldable function.
	 */
	lua_sethook(hlua->T, hlua_hook, LUA_MASKRET|LUA_MASKCOUNT, hlua_nb_instruction);
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

	/* Initialise run time counter. */
	if (!HLUA_IS_RUNNING(lua))
		lua->run_time = 0;

	/* Lock the whole Lua execution. This lock must be before the
	 * label "resume_execution".
	 */
	if (lua->state_id == 0)
		HA_SPIN_LOCK(LUA_LOCK, &hlua_global_lock);

resume_execution:

	/* This hook interrupts the Lua processing each 'hlua_nb_instruction'
	 * instructions. it is used for preventing infinite loops.
	 */
	lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, hlua_nb_instruction);

	/* Remove all flags except the running flags. */
	HLUA_SET_RUN(lua);
	HLUA_CLR_CTRLYIELD(lua);
	HLUA_CLR_WAKERESWR(lua);
	HLUA_CLR_WAKEREQWR(lua);

	/* Update the start time and reset wake_time. */
	lua->start_time = now_ms;
	lua->wake_time = TICK_ETERNITY;

	/* Call the function. */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
	ret = lua_resume(lua->T, hlua_states[lua->state_id], lua->nargs, &nres);
#else
	ret = lua_resume(lua->T, hlua_states[lua->state_id], lua->nargs);
#endif
	switch (ret) {

	case LUA_OK:
		ret = HLUA_E_OK;
		break;

	case LUA_YIELD:
		/* Check if the execution timeout is expired. It it is the case, we
		 * break the Lua execution.
		 */
		tv_update_date(0, 1);
		lua->run_time += now_ms - lua->start_time;
		if (lua->max_time && lua->run_time > lua->max_time) {
			lua_settop(lua->T, 0); /* Empty the stack. */
			ret = HLUA_E_ETMOUT;
			break;
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
		msg = lua_tostring(lua->T, -1);
		lua_settop(lua->T, 0); /* Empty the stack. */
		lua_pop(lua->T, 1);
		trace = hlua_traceback(lua->T);
		if (msg)
			lua_pushfstring(lua->T, "[state-id %d] runtime error: %s from %s", lua->state_id, msg, trace);
		else
			lua_pushfstring(lua->T, "[state-id %d] unknown runtime error from %s", lua->state_id, trace);
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
		msg = lua_tostring(lua->T, -1);
		lua_settop(lua->T, 0); /* Empty the stack. */
		lua_pop(lua->T, 1);
		if (msg)
			lua_pushfstring(lua->T, "[state-id %d] message handler error: %s", lua->state_id, msg);
		else
			lua_pushfstring(lua->T, "[state-id %d] message handler error", lua->state_id);
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
	if (lua->state_id == 0)
		HA_SPIN_UNLOCK(LUA_LOCK, &hlua_global_lock);

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

	HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
	pat_ref_delete(ref, key);
	HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
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

	HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
	pat_ref_delete(ref, key);
	HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
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

	HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
	if (pat_ref_find_elt(ref, key) == NULL)
		pat_ref_add(ref, key, NULL, NULL);
	HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
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

	HA_SPIN_LOCK(PATREF_LOCK, &ref->lock);
	if (pat_ref_find_elt(ref, key) != NULL)
		pat_ref_set(ref, key, value, NULL);
	else
		pat_ref_add(ref, key, value, NULL);
	HA_SPIN_UNLOCK(PATREF_LOCK, &ref->lock);
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
		luaL_where(L, 1);
		lua_pushfstring(L, "'new': %s.", err);
		lua_concat(L, 2);
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
	struct stream_interface *si = appctx->owner;

	if (appctx->ctx.hlua_cosocket.die) {
		si_shutw(si);
		si_shutr(si);
		si_ic(si)->flags |= CF_READ_NULL;
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_read);
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_write);
		stream_shutdown(si_strm(si), SF_ERR_KILLED);
	}

	/* If we can't write, wakeup the pending write signals. */
	if (channel_output_closed(si_ic(si)))
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_write);

	/* If we can't read, wakeup the pending read signals. */
	if (channel_input_closed(si_oc(si)))
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_read);

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (si_opposite(si)->state < SI_ST_EST) {
		si_cant_get(si);
		si_rx_conn_blk(si);
		si_rx_endp_more(si);
		return;
	}

	/* This function is called after the connect. */
	appctx->ctx.hlua_cosocket.connected = 1;

	/* Wake the tasks which wants to write if the buffer have available space. */
	if (channel_may_recv(si_ic(si)))
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_write);

	/* Wake the tasks which wants to read if the buffer contains data. */
	if (!channel_is_empty(si_oc(si)))
		notification_wake(&appctx->ctx.hlua_cosocket.wake_on_read);

	/* Some data were injected in the buffer, notify the stream
	 * interface.
	 */
	if (!channel_is_empty(si_ic(si)))
		si_update(si);

	/* If write notifications are registered, we considers we want
	 * to write, so we clear the blocking flag.
	 */
	if (notification_registered(&appctx->ctx.hlua_cosocket.wake_on_write))
		si_rx_endp_more(si);
}

/* This function is called when the "struct stream" is destroyed.
 * Remove the link from the object to this stream.
 * Wake all the pending signals.
 */
static void hlua_socket_release(struct appctx *appctx)
{
	struct xref *peer;

	/* Remove my link in the original object. */
	peer = xref_get_peer_and_lock(&appctx->ctx.hlua_cosocket.xref);
	if (peer)
		xref_disconnect(&appctx->ctx.hlua_cosocket.xref, peer);

	/* Wake all the task waiting for me. */
	notification_wake(&appctx->ctx.hlua_cosocket.wake_on_read);
	notification_wake(&appctx->ctx.hlua_cosocket.wake_on_write);
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
	struct appctx *appctx;
	struct xref *peer;

	MAY_LJMP(check_args(L, 1, "__gc"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer)
		return 0;
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);

	/* Set the flag which destroy the session. */
	appctx->ctx.hlua_cosocket.die = 1;
	appctx_wakeup(appctx);

	/* Remove all reference between the Lua stack and the coroutine stream. */
	xref_disconnect(&socket->xref, peer);
	return 0;
}

/* The close function send shutdown signal and break the
 * links between the stream and the object.
 */
__LJMP static int hlua_socket_close_helper(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);

	/* Set the flag which destroy the session. */
	appctx->ctx.hlua_cosocket.die = 1;
	appctx_wakeup(appctx);

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
	struct appctx *appctx;
	size_t len;
	int nblk;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;
	int skip_at_end = 0;
	struct channel *oc;
	struct stream_interface *si;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

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

	if (!notification_new(&hlua->com, &appctx->ctx.hlua_cosocket.wake_on_read, hlua->task)) {
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
	int type;
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

	/* init buffer, and fill it with prefix. */
	luaL_buffinit(L, &socket->b);

	/* Check prefix. */
	if (lua_gettop(L) >= 3) {
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
	struct appctx *appctx;
	size_t buf_len;
	const char *buf;
	int len;
	int send_len;
	int sent;
	struct xref *peer;
	struct stream_interface *si;
	struct stream *s;

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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

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
		if (!si_alloc_ibuf(si, &appctx->buffer_wait))
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

	s->req.rex = TICK_ETERNITY;
	s->res.wex = TICK_ETERNITY;

	/* Update length sent. */
	lua_pop(L, 1);
	lua_pushinteger(L, sent + len);

	/* All the data buffer is sent ? */
	if (sent + len >= buf_len) {
		xref_unlock(&socket->xref, peer);
		return 1;
	}

hlua_socket_write_yield_return:
	if (!notification_new(&hlua->com, &appctx->ctx.hlua_cosocket.wake_on_write, hlua->task)) {
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
__LJMP static inline int hlua_socket_info(struct lua_State *L, struct sockaddr_storage *addr)
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
	struct appctx *appctx;
	struct stream_interface *si;
	struct stream *s;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

	if (!s->target_addr) {
		xref_unlock(&socket->xref, peer);
		lua_pushnil(L);
		return 1;
	}

	ret = MAY_LJMP(hlua_socket_info(L, s->target_addr));
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
	struct stream_interface *si;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

	conn = cs_conn(objt_cs(s->si[1].end));
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
	.release = hlua_socket_release,
};

__LJMP static int hlua_socket_connect_yield(struct lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_socket *socket = MAY_LJMP(hlua_checksocket(L, 1));
	struct hlua *hlua;
	struct xref *peer;
	struct appctx *appctx;
	struct stream_interface *si;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

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

	appctx = __objt_appctx(s->si[0].end);

	/* Check for connection established. */
	if (appctx->ctx.hlua_cosocket.connected) {
		xref_unlock(&socket->xref, peer);
		lua_pushinteger(L, 1);
		return 1;
	}

	if (!notification_new(&hlua->com, &appctx->ctx.hlua_cosocket.wake_on_write, hlua->task)) {
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
	struct appctx *appctx;
	int low, high;
	struct sockaddr_storage *addr;
	struct xref *peer;
	struct stream_interface *si;
	struct stream *s;

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

	/* Parse ip address. */
	addr = str2sa_range(ip, NULL, &low, &high, NULL, NULL, NULL, NULL, NULL, PA_O_PORT_OK | PA_O_STREAM);
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

	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

	if (!sockaddr_alloc(&s->target_addr, addr, sizeof(*addr))) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "connect: internal error"));
	}
	s->flags |= SF_ADDR_SET;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 0;

	/* inform the stream that we want to be notified whenever the
	 * connection completes.
	 */
	si_cant_get(&s->si[0]);
	si_rx_endp_more(&s->si[0]);
	appctx_wakeup(appctx);

	hlua->gc_count++;

	if (!notification_new(&hlua->com, &appctx->ctx.hlua_cosocket.wake_on_write, hlua->task)) {
		xref_unlock(&socket->xref, peer);
		WILL_LJMP(luaL_error(L, "out of memory"));
	}
	xref_unlock(&socket->xref, peer);

	task_wakeup(s->task, TASK_WOKEN_INIT);
	/* Return yield waiting for connection. */

	MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));

	return 0;
}

#ifdef USE_OPENSSL
__LJMP static int hlua_socket_connect_ssl(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct xref *peer;
	struct appctx *appctx;
	struct stream_interface *si;
	struct stream *s;

	MAY_LJMP(check_args(L, 3, "connect_ssl"));
	socket  = MAY_LJMP(hlua_checksocket(L, 1));

	/* check for connection break. If some data where read, return it. */
	peer = xref_get_peer_and_lock(&socket->xref);
	if (!peer) {
		lua_pushnil(L);
		return 1;
	}
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

	s->target = &socket_ssl.obj_type;
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
	struct appctx *appctx;
	struct stream_interface *si;
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
	appctx = container_of(peer, struct appctx, ctx.hlua_cosocket.xref);
	si = appctx->owner;
	s = si_strm(si);

	s->sess->fe->timeout.connect = tmout;
	s->req.rto = tmout;
	s->req.wto = tmout;
	s->res.rto = tmout;
	s->res.wto = tmout;
	s->req.rex = tick_add_ifset(now_ms, tmout);
	s->req.wex = tick_add_ifset(now_ms, tmout);
	s->res.rex = tick_add_ifset(now_ms, tmout);
	s->res.wex = tick_add_ifset(now_ms, tmout);

	s->task->expire = tick_add_ifset(now_ms, tmout);
	task_queue(s->task);

	xref_unlock(&socket->xref, peer);

	lua_pushinteger(L, 1);
	return 1;
}

__LJMP static int hlua_socket_new(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;
	struct session *sess;
	struct stream *strm;

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
	appctx = appctx_new(&update_applet, tid_bit);
	if (!appctx) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_conf;
	}

	appctx->ctx.hlua_cosocket.connected = 0;
	appctx->ctx.hlua_cosocket.die = 0;
	LIST_INIT(&appctx->ctx.hlua_cosocket.wake_on_write);
	LIST_INIT(&appctx->ctx.hlua_cosocket.wake_on_read);

	/* Now create a session, task and stream for this applet */
	sess = session_new(&socket_proxy, NULL, &appctx->obj_type);
	if (!sess) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_sess;
	}

	strm = stream_new(sess, &appctx->obj_type, &BUF_NULL);
	if (!strm) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_stream;
	}

	/* Initialise cross reference between stream and Lua socket object. */
	xref_create(&socket->xref, &appctx->ctx.hlua_cosocket.xref);

	/* Configure "right" stream interface. this "si" is used to connect
	 * and retrieve data from the server. The connection is initialized
	 * with the "struct server".
	 */
	si_set_state(&strm->si[1], SI_ST_ASS);

	/* Force destination server. */
	strm->flags |= SF_DIRECT | SF_ASSIGNED | SF_BE_ASSIGNED;
	strm->target = &socket_tcp.obj_type;

	return 1;

 out_fail_stream:
	session_free(sess);
 out_fail_sess:
	appctx_free(appctx);
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
static int hlua_channel_new(lua_State *L, struct channel *channel)
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

/* Duplicate all the data present in the input channel and put it
 * in a string LUA variables. Returns -1 and push a nil value in
 * the stack if the channel is closed and all the data are consumed,
 * returns 0 if no data are available, otherwise it returns the length
 * of the built string.
 */
static inline int _hlua_channel_dup(struct channel *chn, lua_State *L)
{
	char *blk1;
	char *blk2;
	size_t len1;
	size_t len2;
	int ret;
	luaL_Buffer b;

	ret = ci_getblk_nc(chn, &blk1, &len1, &blk2, &len2);
	if (unlikely(ret == 0))
		return 0;

	if (unlikely(ret < 0)) {
		lua_pushnil(L);
		return -1;
	}

	luaL_buffinit(L, &b);
	luaL_addlstring(&b, blk1, len1);
	if (unlikely(ret == 2))
		luaL_addlstring(&b, blk2, len2);
	luaL_pushresult(&b);

	if (unlikely(ret == 2))
		return len1 + len2;
	return len1;
}

/* "_hlua_channel_dup" wrapper. If no data are available, it returns
 * a yield. This function keep the data in the buffer.
 */
__LJMP static int hlua_channel_dup_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	if (_hlua_channel_dup(chn, L) == 0)
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_dup_yield, TICK_ETERNITY, 0));
	return 1;
}

/* Check arguments for the function "hlua_channel_dup_yield". */
__LJMP static int hlua_channel_dup(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "dup"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_dup_yield(L, 0, 0));
}

/* "_hlua_channel_dup" wrapper. If no data are available, it returns
 * a yield. This function consumes the data in the buffer. It returns
 * a string containing the data or a nil pointer if no data are available
 * and the channel is closed.
 */
__LJMP static int hlua_channel_get_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	int ret;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	ret = _hlua_channel_dup(chn, L);
	if (unlikely(ret == 0))
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_get_yield, TICK_ETERNITY, 0));

	if (unlikely(ret == -1))
		return 1;

	b_sub(&chn->buf, ret);
	return 1;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_channel_get(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "get"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_get_yield(L, 0, 0));
}

/* This functions consumes and returns one line. If the channel is closed,
 * and the last data does not contains a final '\n', the data are returned
 * without the final '\n'. When no more data are available, it returns nil
 * value.
 */
__LJMP static int hlua_channel_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	char *blk1;
	char *blk2;
	size_t len1;
	size_t len2;
	size_t len;
	struct channel *chn;
	int ret;
	luaL_Buffer b;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	ret = ci_getline_nc(chn, &blk1, &len1, &blk2, &len2);
	if (ret == 0)
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_getline_yield, TICK_ETERNITY, 0));

	if (ret == -1) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	luaL_addlstring(&b, blk1, len1);
	len = len1;
	if (unlikely(ret == 2)) {
		luaL_addlstring(&b, blk2, len2);
		len += len2;
	}
	luaL_pushresult(&b);
	b_rep_blk(&chn->buf, ci_head(chn), ci_head(chn) + len,  NULL, 0);
	return 1;
}

/* Check arguments for the function "hlua_channel_getline_yield". */
__LJMP static int hlua_channel_getline(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "getline"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_getline_yield(L, 0, 0));
}

/* This function takes a string as input, and append it at the
 * input side of channel. If the data is too big, but a space
 * is probably available after sending some data, the function
 * yields. If the data is bigger than the buffer, or if the
 * channel is closed, it returns -1. Otherwise, it returns the
 * amount of data written.
 */
__LJMP static int hlua_channel_append_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int ret;
	int max;

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	/* Check if the buffer is available because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (chn->buf.size == 0) {
		si_rx_buff_blk(chn_prod(chn));
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	}

	max = channel_recv_limit(chn) - b_data(&chn->buf);
	if (max > len - l)
		max = len - l;

	ret = ci_putblk(chn, str + l, max);
	if (ret == -2 || ret == -3) {
		lua_pushinteger(L, -1);
		return 1;
	}
	if (ret == -1) {
		chn->flags |= CF_WAKE_WRITE;
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	}
	l += ret;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	max = channel_recv_limit(chn) - b_data(&chn->buf);
	if (max == 0 && co_data(chn) == 0) {
		/* There are no space available, and the output buffer is empty.
		 * in this case, we cannot add more data, so we cannot yield,
		 * we return the amount of copied data.
		 */
		return 1;
	}
	if (l < len)
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	return 1;
}

/* Just a wrapper of "hlua_channel_append_yield". It returns the length
 * of the written string, or -1 if the channel is closed or if the
 * buffer size is too little for the data.
 */
__LJMP static int hlua_channel_append(lua_State *L)
{
	size_t len;

	MAY_LJMP(check_args(L, 2, "append"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	MAY_LJMP(luaL_checklstring(L, 2, &len));
	MAY_LJMP(luaL_checkinteger(L, 3));
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_channel_append_yield(L, 0, 0));
}

/* Just a wrapper of "hlua_channel_append_yield". This wrapper starts
 * his process by cleaning the buffer. The result is a replacement
 * of the current data. It returns the length of the written string,
 * or -1 if the channel is closed or if the buffer size is too
 * little for the data.
 */
__LJMP static int hlua_channel_set(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "set"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, 0);

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	b_set_data(&chn->buf, co_data(chn));

	return MAY_LJMP(hlua_channel_append_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediately
 * sent. The function returns the amount of data written. If the buffer
 * cannot contain the data, the function yields. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_channel_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int max;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua) {
		lua_pushnil(L);
		return 1;
	}

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	if (unlikely(channel_output_closed(chn))) {
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Check if the buffer is available because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (chn->buf.size == 0) {
		si_rx_buff_blk(chn_prod(chn));
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
	}

	/* The written data will be immediately sent, so we can check
	 * the available space without taking in account the reserve.
	 * The reserve is guaranteed for the processing of incoming
	 * data, because the buffer will be flushed.
	 */
	max = b_room(&chn->buf);

	/* If there is no space available, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copied data.
	 */
	if (max == 0 && co_data(chn) == 0)
		return 1;

	/* Adjust the real required length. */
	if (max > len - l)
		max = len - l;

	/* The buffer available size may be not contiguous. This test
	 * detects a non contiguous buffer and realign it.
	 */
	if (ci_space_for_replace(chn) < max)
		channel_slow_realign(chn, trash.area);

	/* Copy input data in the buffer. */
	max = b_rep_blk(&chn->buf, ci_head(chn), ci_head(chn), str + l, max);

	/* buffer replace considers that the input part is filled.
	 * so, I must forward these new data in the output part.
	 */
	c_adv(chn, max);

	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If there is no space available, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copied data.
	 */
	max = b_room(&chn->buf);
	if (max == 0 && co_data(chn) == 0)
		return 1;

	if (l < len) {
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
 */
__LJMP static int hlua_channel_send(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "send"));
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
	int len;
	int l;
	int max;
	struct hlua *hlua;

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);
	if (!hlua)
		return 1;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (chn_strm(chn)->be->mode == PR_MODE_HTTP) {
		lua_pushfstring(L, "Cannot manipulate HAProxy channels in HTTP mode.");
		WILL_LJMP(lua_error(L));
	}

	len = MAY_LJMP(luaL_checkinteger(L, 2));
	l = MAY_LJMP(luaL_checkinteger(L, -1));

	max = len - l;
	if (max > ci_data(chn))
		max = ci_data(chn);
	channel_forward(chn, max);
	l += max;

	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* Check if it miss bytes to forward. */
	if (l < len) {
		/* The the input channel or the output channel are closed, we
		 * must return the amount of data forwarded.
		 */
		if (channel_input_closed(chn) || channel_output_closed(chn))
			return 1;

		/* If we are waiting for space data in the response buffer, we
		 * must set the flag WAKERESWR. This flag required the task
		 * wake up if any activity is detected on the response buffer.
		 */
		if (chn->flags & CF_ISRESP)
			HLUA_SET_WAKERESWR(hlua);
		else
			HLUA_SET_WAKEREQWR(hlua);

		/* Otherwise, we can yield waiting for new data in the inpout side. */
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_forward_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just check the input and prepare the stack for the previous
 * function "hlua_channel_forward_yield"
 */
__LJMP static int hlua_channel_forward(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "forward"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	MAY_LJMP(luaL_checkinteger(L, 2));

	lua_pushinteger(L, 0);
	return MAY_LJMP(hlua_channel_forward_yield(L, 0, 0));
}

/* Just returns the number of bytes available in the input
 * side of the buffer. This function never fails.
 */
__LJMP static int hlua_channel_get_in_len(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 1, "get_in_len"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	if (IS_HTX_STRM(chn_strm(chn))) {
		struct htx *htx = htxbuf(&chn->buf);
		lua_pushinteger(L, htx->data - co_data(chn));
	}
	else
		lua_pushinteger(L, ci_data(chn));
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

	MAY_LJMP(check_args(L, 1, "get_out_len"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, co_data(chn));
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
static int hlua_fetches_new(lua_State *L, struct hlua_txn *txn, unsigned int flags)
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
		lua_pushfstring(L, "error in arguments");
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
		hlua_smp2lua_str(L, &smp);
	else
		hlua_smp2lua(L, &smp);

  end:
	for (i = 0; args[i].type != ARGT_STOP; i++) {
		if (args[i].type == ARGT_STR)
			chunk_destroy(&args[i].data.str);
		else if (args[i].type == ARGT_REG)
			regex_free(args[i].data.reg);
	}
	return 1;

  error:
	for (i = 0; args[i].type != ARGT_STOP; i++) {
		if (args[i].type == ARGT_STR)
			chunk_destroy(&args[i].data.str);
		else if (args[i].type == ARGT_REG)
			regex_free(args[i].data.reg);
	}
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
static int hlua_converters_new(lua_State *L, struct hlua_txn *txn, unsigned int flags)
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
		hlua_smp2lua_str(L, &smp);
	else
		hlua_smp2lua(L, &smp);
  end:
	for (i = 0; args[i].type != ARGT_STOP; i++) {
		if (args[i].type == ARGT_STR)
			chunk_destroy(&args[i].data.str);
		else if (args[i].type == ARGT_REG)
			regex_free(args[i].data.reg);
	}
	return 1;

  error:
	for (i = 0; args[i].type != ARGT_STOP; i++) {
		if (args[i].type == ARGT_STR)
			chunk_destroy(&args[i].data.str);
		else if (args[i].type == ARGT_REG)
			regex_free(args[i].data.reg);
	}
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
	struct hlua_appctx *appctx;
	struct stream_interface *si = ctx->owner;
	struct stream *s = si_strm(si);
	struct proxy *p = s->be;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	appctx = lua_newuserdata(L, sizeof(*appctx));
	lua_rawseti(L, -2, 0);
	appctx->appctx = ctx;
	appctx->htxn.s = s;
	appctx->htxn.p = p;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, &appctx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, &appctx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, &appctx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, &appctx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_applet_tcp_ref);
	lua_setmetatable(L, -2);

	return 1;
}

__LJMP static int hlua_applet_tcp_set_var(lua_State *L)
{
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set_var' needs between 3 and 4 arguments"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	/* Converts the third argument in a sample. */
	memset(&smp, 0, sizeof(smp));
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);

	if (lua_gettop(L) == 4 && lua_toboolean(L, 4))
		lua_pushboolean(L, vars_set_by_name_ifexist(name, len, &smp) != 0);
	else
		lua_pushboolean(L, vars_set_by_name(name, len, &smp) != 0);

	return 1;
}

__LJMP static int hlua_applet_tcp_unset_var(lua_State *L)
{
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "unset_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	/* Unset the variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);
	lua_pushboolean(L, vars_unset_by_name_ifexist(name, len, &smp) != 0);
	return 1;
}

__LJMP static int hlua_applet_tcp_get_var(lua_State *L)
{
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "get_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	smp_set_owner(&smp, s->be, s->sess, s, 0);
	if (!vars_get_by_name(name, len, &smp)) {
		lua_pushnil(L);
		return 1;
	}

	return hlua_smp2lua(L, &smp);
}

__LJMP static int hlua_applet_tcp_set_priv(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stream *s = appctx->htxn.s;
	struct hlua *hlua;

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!s->hlua)
		return 0;
	hlua = s->hlua;

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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stream *s = appctx->htxn.s;
	struct hlua *hlua;

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!s->hlua) {
		lua_pushnil(L);
		return 1;
	}
	hlua = s->hlua;

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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	int ret;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;

	/* Read the maximum amount of data available. */
	ret = co_getline_nc(si_oc(si), &blk1, &len1, &blk2, &len2);

	/* Data not yet available. return yield. */
	if (ret == 0) {
		si_cant_get(si);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_getline_yield, TICK_ETERNITY, 0));
	}

	/* End of data: commit the total strings and return. */
	if (ret < 0) {
		luaL_pushresult(&appctx->b);
		return 1;
	}

	/* Ensure that the block 2 length is usable. */
	if (ret == 1)
		len2 = 0;

	/* dont check the max length read and dont check. */
	luaL_addlstring(&appctx->b, blk1, len1);
	luaL_addlstring(&appctx->b, blk2, len2);

	/* Consume input channel output buffer data. */
	co_skip(si_oc(si), len1 + len2);
	luaL_pushresult(&appctx->b);
	return 1;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_tcp_getline(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));

	/* Initialise the string catenation. */
	luaL_buffinit(L, &appctx->b);

	return MAY_LJMP(hlua_applet_tcp_getline_yield(L, 0, 0));
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_tcp_recv_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	size_t len = MAY_LJMP(luaL_checkinteger(L, 2));
	int ret;
	const char *blk1;
	size_t len1;
	const char *blk2;
	size_t len2;

	/* Read the maximum amount of data available. */
	ret = co_getblk_nc(si_oc(si), &blk1, &len1, &blk2, &len2);

	/* Data not yet available. return yield. */
	if (ret == 0) {
		si_cant_get(si);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));
	}

	/* End of data: commit the total strings and return. */
	if (ret < 0) {
		luaL_pushresult(&appctx->b);
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
		luaL_addlstring(&appctx->b, blk1, len1);
		luaL_addlstring(&appctx->b, blk2, len2);
		co_skip(si_oc(si), len1 + len2);
		si_cant_get(si);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));

	} else {

		/* Copy the first block caping to the length required. */
		if (len1 > len)
			len1 = len;
		luaL_addlstring(&appctx->b, blk1, len1);
		len -= len1;

		/* Copy the second block. */
		if (len2 > len)
			len2 = len;
		luaL_addlstring(&appctx->b, blk2, len2);
		len -= len2;

		/* Consume input channel output buffer data. */
		co_skip(si_oc(si), len1 + len2);

		/* If there is no other data available, yield waiting for new data. */
		if (len > 0) {
			lua_pushinteger(L, len);
			lua_replace(L, 2);
			si_cant_get(si);
			MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_tcp_recv_yield, TICK_ETERNITY, 0));
		}

		/* return the result. */
		luaL_pushresult(&appctx->b);
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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
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
	luaL_buffinit(L, &appctx->b);

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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_tcp(L, 1));
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *chn = si_ic(si);
	int max;

	/* Get the max amount of data which can write as input in the channel. */
	max = channel_recv_max(chn);
	if (max > (len - l))
		max = len - l;

	/* Copy data. */
	ci_putblk(chn, str + l, max);

	/* update counters. */
	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If some data is not send, declares the situation to the
	 * applet, and returns a yield.
	 */
	if (l < len) {
		si_rx_room_blk(si);
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
 */
static int hlua_applet_http_new(lua_State *L, struct appctx *ctx)
{
	struct hlua_appctx *appctx;
	struct hlua_txn htxn;
	struct stream_interface *si = ctx->owner;
	struct stream *s = si_strm(si);
	struct proxy *px = s->be;
	struct htx *htx;
	struct htx_blk *blk;
	struct htx_sl *sl;
	struct ist path;
	unsigned long long len = 0;
	int32_t pos;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* Create the object: obj[0] = userdata.
	 * Note that the base of the Converters object is the
	 * same than the TXN object.
	 */
	lua_newtable(L);
	appctx = lua_newuserdata(L, sizeof(*appctx));
	lua_rawseti(L, -2, 0);
	appctx->appctx = ctx;
	appctx->appctx->ctx.hlua_apphttp.status = 200; /* Default status code returned. */
	appctx->appctx->ctx.hlua_apphttp.reason = NULL; /* Use default reason based on status */
	appctx->htxn.s = s;
	appctx->htxn.p = px;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, &appctx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, &appctx->htxn, HLUA_F_AS_STRING))
		return 0;
	lua_settable(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, &appctx->htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, &appctx->htxn, HLUA_F_AS_STRING))
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

	path = http_get_path(htx_sl_req_uri(sl));
	if (isttest(path)) {
		char *p, *q, *end;

		p = path.ptr;
		end = path.ptr + path.len;
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

		if (type == HTX_BLK_EOM || type == HTX_BLK_TLR || type == HTX_BLK_EOT)
			break;
		if (type == HTX_BLK_DATA)
			len += htx_get_blksz(blk);
	}
	if (htx->extra != ULLONG_MAX)
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
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'set_var' needs between 3 and 4 arguments"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	/* Converts the third argument in a sample. */
	memset(&smp, 0, sizeof(smp));
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);

	if (lua_gettop(L) == 4 && lua_toboolean(L, 4))
		lua_pushboolean(L, vars_set_by_name_ifexist(name, len, &smp) != 0);
	else
		lua_pushboolean(L, vars_set_by_name(name, len, &smp) != 0);

	return 1;
}

__LJMP static int hlua_applet_http_unset_var(lua_State *L)
{
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "unset_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	/* Unset the variable. */
	smp_set_owner(&smp, s->be, s->sess, s, 0);
	lua_pushboolean(L, vars_unset_by_name_ifexist(name, len, &smp) != 0);
	return 1;
}

__LJMP static int hlua_applet_http_get_var(lua_State *L)
{
	struct hlua_appctx *appctx;
	struct stream *s;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 2, "get_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	s = appctx->htxn.s;

	smp_set_owner(&smp, s->be, s->sess, s, 0);
	if (!vars_get_by_name(name, len, &smp)) {
		lua_pushnil(L);
		return 1;
	}

	return hlua_smp2lua(L, &smp);
}

__LJMP static int hlua_applet_http_set_priv(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream *s = appctx->htxn.s;
	struct hlua *hlua;

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!s->hlua)
		return 0;
	hlua = s->hlua;

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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream *s = appctx->htxn.s;
	struct hlua *hlua;

	/* Note that this hlua struct is from the session and not from the applet. */
	if (!s->hlua) {
		lua_pushnil(L);
		return 1;
	}
	hlua = s->hlua;

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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *req = si_oc(si);
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

		if (type == HTX_BLK_EOM) {
			stop = 1;
			break;
		}

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
				luaL_addlstring(&appctx->b, v.ptr, vlen);
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOM:
				stop = 1;
				break;

			default:
				break;
		}

		co_set_data(req, co_data(req) - vlen);
		count -= vlen;
		if (sz == vlen)
			blk = htx_remove_blk(htx, blk);
		else {
			htx_cut_data_blk(htx, blk, vlen);
			break;
		}
	}

	htx_to_buf(htx, &req->buf);
	if (!stop) {
		si_cant_get(si);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_getline_yield, TICK_ETERNITY, 0));
	}

	/* return the result. */
	luaL_pushresult(&appctx->b);
	return 1;
}


/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_http_getline(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));

	/* Initialise the string catenation. */
	luaL_buffinit(L, &appctx->b);

	return MAY_LJMP(hlua_applet_http_getline_yield(L, 0, 0));
}

/* If expected data not yet available, it returns a yield. This function
 * consumes the data in the buffer. It returns a string containing the
 * data. This string can be empty.
 */
__LJMP static int hlua_applet_http_recv_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *req = si_oc(si);
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

		if (type == HTX_BLK_EOM) {
			len = 0;
			break;
		}

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
				luaL_addlstring(&appctx->b, v.ptr, vlen);
				break;

			case HTX_BLK_TLR:
			case HTX_BLK_EOM:
				len = 0;
				break;

			default:
				break;
		}

		co_set_data(req, co_data(req) - vlen);
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

	htx_to_buf(htx, &req->buf);

	/* If we are no other data available, yield waiting for new data. */
	if (len) {
		if (len > 0) {
			lua_pushinteger(L, len);
			lua_replace(L, 2);
		}
		si_cant_get(si);
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_applet_http_recv_yield, TICK_ETERNITY, 0));
	}

	/* return the result. */
	luaL_pushresult(&appctx->b);
	return 1;
}

/* Check arguments for the function "hlua_channel_get_yield". */
__LJMP static int hlua_applet_http_recv(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
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
	luaL_buffinit(L, &appctx->b);

	return MAY_LJMP(hlua_applet_http_recv_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediately
 * sent. The function returns the amount of data written. If the buffer
 * cannot contain the data, the function yields. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_applet_http_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *res = si_ic(si);
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
		si_rx_room_blk(si);
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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));

	/* We want to send some data. Headers must be sent. */
	if (!(appctx->appctx->ctx.hlua_apphttp.flags & APPLET_HDR_SENT)) {
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

	/* Now the top od thestack is an array of values. We push
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
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	int status = MAY_LJMP(luaL_checkinteger(L, 2));
	const char *reason = MAY_LJMP(luaL_optlstring(L, 3, NULL, NULL));

	if (status < 100 || status > 599) {
		lua_pushboolean(L, 0);
		return 1;
	}

	appctx->appctx->ctx.hlua_apphttp.status = status;
	appctx->appctx->ctx.hlua_apphttp.reason = reason;
	lua_pushboolean(L, 1);
	return 1;
}


__LJMP static int hlua_applet_http_send_response(lua_State *L)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *res = si_ic(si);
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
	status = ultoa_r(appctx->appctx->ctx.hlua_apphttp.status, trash.area, trash.size);
	reason = appctx->appctx->ctx.hlua_apphttp.reason;
	if (reason == NULL)
		reason = http_get_reason(appctx->appctx->ctx.hlua_apphttp.status);
	if (appctx->appctx->ctx.hlua_apphttp.flags & APPLET_HTTP11) {
		flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist(status), ist(reason));
	}
	else {
		flags = HTX_SL_F_IS_RESP;
		sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.0"), ist(status), ist(reason));
	}
	if (!sl) {
		hlua_pusherror(L, "Lua applet http '%s': Failed to create response.\n",
		               appctx->appctx->rule->arg.hlua_rule->fcn->name);
		WILL_LJMP(lua_error(L));
	}
	sl->info.res.status = appctx->appctx->ctx.hlua_apphttp.status;

	/* Get the array associated to the field "response" in the object AppletHTTP. */
	lua_pushvalue(L, 0);
	if (lua_getfield(L, 1, "response") != LUA_TTABLE) {
		hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response'] missing.\n",
		               appctx->appctx->rule->arg.hlua_rule->fcn->name);
		WILL_LJMP(lua_error(L));
	}

	/* Browse the list of headers. */
	lua_pushnil(L);
	while(lua_next(L, -2) != 0) {
		/* We expect a string as -2. */
		if (lua_type(L, -2) != LUA_TSTRING) {
			hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response'][] element must be a string. got %s.\n",
				       appctx->appctx->rule->arg.hlua_rule->fcn->name,
			               lua_typename(L, lua_type(L, -2)));
			WILL_LJMP(lua_error(L));
		}
		name = lua_tolstring(L, -2, &nlen);

		/* We expect an array as -1. */
		if (lua_type(L, -1) != LUA_TTABLE) {
			hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response']['%s'] element must be an table. got %s.\n",
				       appctx->appctx->rule->arg.hlua_rule->fcn->name,
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
					       appctx->appctx->rule->arg.hlua_rule->fcn->name,
					       name,
				               lua_typename(L, lua_type(L, -2)));
				WILL_LJMP(lua_error(L));
			}
			id = lua_tointeger(L, -2);

			/* We expect a string as -2. */
			if (lua_type(L, -1) != LUA_TSTRING) {
				hlua_pusherror(L, "Lua applet http '%s': AppletHTTP['response']['%s'][%d] element must be a string. got %s.\n",
					       appctx->appctx->rule->arg.hlua_rule->fcn->name,
					       name, id,
				               lua_typename(L, lua_type(L, -1)));
				WILL_LJMP(lua_error(L));
			}
			value = lua_tolstring(L, -1, &vlen);

			/* Simple Protocol checks. */
			if (isteqi(ist2(name, nlen), ist("transfer-encoding")))
				h1_parse_xfer_enc_header(&h1m, ist2(value, vlen));
			else if (isteqi(ist2(name, nlen), ist("content-length"))) {
				struct ist v = ist2(value, vlen);
				int ret;

				ret = h1_parse_cont_len_header(&h1m, &v);
				if (ret < 0) {
					hlua_pusherror(L, "Lua applet http '%s': Invalid '%s' header.\n",
						       appctx->appctx->rule->arg.hlua_rule->fcn->name,
						       name);
					WILL_LJMP(lua_error(L));
				}
				else if (ret == 0)
					goto next; /* Skip it */
			}

			/* Add a new header */
			if (!htx_add_header(htx, ist2(name, nlen), ist2(value, vlen))) {
				hlua_pusherror(L, "Lua applet http '%s': Failed to add header '%s' in the response.\n",
					       appctx->appctx->rule->arg.hlua_rule->fcn->name,
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

	/* If we dont have a content-length set, and the HTTP version is 1.1
	 * and the status code implies the presence of a message body, we must
	 * announce a transfer encoding chunked. This is required by haproxy
	 * for the keepalive compliance. If the applet announces a transfer-encoding
	 * chunked itself, don't do anything.
	 */
	if ((flags & (HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN)) == HTX_SL_F_VER_11 &&
	    appctx->appctx->ctx.hlua_apphttp.status >= 200 &&
	    appctx->appctx->ctx.hlua_apphttp.status != 204 &&
	    appctx->appctx->ctx.hlua_apphttp.status != 304) {
		/* Add a new header */
		sl->flags |= (HTX_SL_F_XFER_ENC|H1_MF_CHNK|H1_MF_XFER_LEN);
		if (!htx_add_header(htx, ist("transfer-encoding"), ist("chunked"))) {
			hlua_pusherror(L, "Lua applet http '%s': Failed to add header 'transfer-encoding' in the response.\n",
				       appctx->appctx->rule->arg.hlua_rule->fcn->name);
			WILL_LJMP(lua_error(L));
		}
	}

	/* Finalize headers. */
	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		hlua_pusherror(L, "Lua applet http '%s': Failed create the response.\n",
			       appctx->appctx->rule->arg.hlua_rule->fcn->name);
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
	appctx->appctx->ctx.hlua_apphttp.flags |= APPLET_HDR_SENT;
	return 0;

}
/* We will build the status line and the headers of the HTTP response.
 * We will try send at once if its not possible, we give back the hand
 * waiting for more room.
 */
__LJMP static int hlua_applet_http_start_response_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_appctx *appctx = MAY_LJMP(hlua_checkapplet_http(L, 1));
	struct stream_interface *si = appctx->appctx->owner;
	struct channel *res = si_ic(si);

	if (co_data(res)) {
		si_rx_room_blk(si);
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
static int hlua_http_new(lua_State *L, struct hlua_txn *txn)
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

	/* Store the sample in a variable. */
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
	if (!vars_get_by_name(name, len, &smp)) {
		lua_pushnil(L);
		return 1;
	}

	return hlua_smp2lua(L, &smp);
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
static int hlua_txn_new(lua_State *L, struct stream *s, struct proxy *p, int dir, int flags)
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
	if (p->mode == PR_MODE_HTTP) {
		if (!hlua_http_new(L, htxn))
			return 0;
	}
	else
		lua_pushnil(L);
	lua_rawset(L, -3);

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

__LJMP static int hlua_txn_set_loglevel(lua_State *L)
{
	struct hlua_txn *htxn;
	int ll;

	MAY_LJMP(check_args(L, 2, "set_loglevel"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	ll = MAY_LJMP(luaL_checkinteger(L, 2));

	if (ll < 0 || ll > 7)
		WILL_LJMP(luaL_argerror(L, 2, "Bad log level. It must be between 0 and 7"));

	htxn->s->logs.level = ll;
	return 0;
}

__LJMP static int hlua_txn_set_tos(lua_State *L)
{
	struct hlua_txn *htxn;
	int tos;

	MAY_LJMP(check_args(L, 2, "set_tos"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	tos = MAY_LJMP(luaL_checkinteger(L, 2));

	conn_set_tos(objt_conn(htxn->s->sess->origin), tos);
	return 0;
}

__LJMP static int hlua_txn_set_mark(lua_State *L)
{
	struct hlua_txn *htxn;
	int mark;

	MAY_LJMP(check_args(L, 2, "set_mark"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	mark = MAY_LJMP(luaL_checkinteger(L, 2));

	conn_set_mark(objt_conn(htxn->s->sess->origin), mark);
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
	    (body_len && !htx_add_data_atonce(htx, ist2(body, body_len))) ||
	    !htx_add_endof(htx, HTX_BLK_EOM))
		goto fail;

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
		channel_auto_close(req);
		channel_erase(req);

		res->wex = tick_add_ifset(now_ms, res->wto);
		channel_auto_read(res);
		channel_auto_close(res);
		channel_shutr_now(res);

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
		s->logs.tv_request = now;
		if (s->sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			_HA_ATOMIC_ADD(&s->sess->fe->fe_counters.intercepted_req, 1);
	}

  done:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_LOCAL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= finst;

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
static int hlua_txn_reply_new(lua_State *L)
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
	luaL_checktype(L, 1, LUA_TTABLE);

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
	luaL_checktype(L, 1, LUA_TTABLE);

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

	/* Now the top od thestack is an array of values. We push
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
	luaL_checktype(L, 1, LUA_TTABLE);

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
	luaL_checktype(L, 1, LUA_TTABLE);

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
	if (now_ms < wakeup_ms)
		MAY_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

__LJMP static int hlua_sleep(lua_State *L)
{
	unsigned int delay;
	unsigned int wakeup_ms;

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
	unsigned int wakeup_ms;

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

/* This function is used as a callback of a task. It is called by the
 * HAProxy task subsystem when the task is awaked. The LUA runtime can
 * return an E_AGAIN signal, the emmiter of this signal must set a
 * signal to wake the task.
 *
 * Task wrapper are longjmp safe because the only one Lua code
 * executed is the safe hlua_ctx_resume();
 */
struct task *hlua_process_task(struct task *task, void *context, unsigned short state)
{
	struct hlua *hlua = context;
	enum hlua_exec status;

	if (task->thread_mask == MAX_THREADS_MASK)
		task_set_affinity(task, tid_bit);

	/* If it is the first call to the task, we must initialize the
	 * execution timeouts.
	 */
	if (!HLUA_IS_RUNNING(hlua))
		hlua->max_time = hlua_timeout_task;

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
	case HLUA_E_ERRMSG:
		SEND_ERR(NULL, "Lua task: %s.\n", lua_tostring(hlua->T, -1));
		hlua_ctx_destroy(hlua);
		task_destroy(task);
		task = NULL;
		break;

	case HLUA_E_ERR:
	default:
		SEND_ERR(NULL, "Lua task: unknown error.\n");
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

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	init = calloc(1, sizeof(*init));
	if (!init)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	init->function_ref = ref;
	LIST_ADDQ(&hlua_init_functions[hlua_state_id], &init->l);
	return 0;
}

/* This functio is an LUA binding. It permits to register a task
 * executed in parallel of the main HAroxy activity. The task is
 * created and it is set in the HAProxy scheduler. It can be called
 * from the "init" section, "post init" or during the runtime.
 *
 * Lua prototype:
 *
 *   <none> core.register_task(<function>)
 */
static int hlua_register_task(lua_State *L)
{
	struct hlua *hlua;
	struct task *task;
	int ref;
	int state_id;

	MAY_LJMP(check_args(L, 1, "register_task"));

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

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
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* We are in the common lua state, execute the task anywhere,
	 * otherwise, inherit the current thread identifier
	 */
	if (state_id == 0)
		task = task_new(MAX_THREADS_MASK);
	else
		task = task_new(tid_bit);
	if (!task)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	task->context = hlua;
	task->process = hlua_process_task;

	if (!hlua_ctx_init(hlua, state_id, task, 1))
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Restore the function in the stack. */
	lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, ref);
	hlua->nargs = 0;

	/* Schedule task. */
	task_schedule(task, now_ms);

	return 0;
}

/* Wrapper called by HAProxy to execute an LUA converter. This wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume converters.
 */
static int hlua_sample_conv_wrapper(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct hlua_function *fcn = private;
	struct stream *stream = smp->strm;
	const char *error;

	if (!stream)
		return 0;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!stream->hlua) {
		stream->hlua = pool_alloc(pool_head_hlua);
		if (!stream->hlua) {
			SEND_ERR(stream->be, "Lua converter '%s': can't initialize Lua context.\n", fcn->name);
			return 0;
		}
		if (!hlua_ctx_init(stream->hlua, fcn_ref_to_stack_id(fcn), stream->task, 0)) {
			SEND_ERR(stream->be, "Lua converter '%s': can't initialize Lua context.\n", fcn->name);
			return 0;
		}
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(stream->hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(stream->hlua)) {
			if (lua_type(stream->hlua->T, -1) == LUA_TSTRING)
				error = lua_tostring(stream->hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(stream->be, "Lua converter '%s': %s.\n", fcn->name, error);
			return 0;
		}

		/* Check stack available size. */
		if (!lua_checkstack(stream->hlua->T, 1)) {
			SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(stream->hlua);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(stream->hlua->T, LUA_REGISTRYINDEX, fcn->function_ref[stream->hlua->state_id]);

		/* convert input sample and pust-it in the stack. */
		if (!lua_checkstack(stream->hlua->T, 1)) {
			SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(stream->hlua);
			return 0;
		}
		hlua_smp2lua(stream->hlua->T, smp);
		stream->hlua->nargs = 1;

		/* push keywords in the stack. */
		if (arg_p) {
			for (; arg_p->type != ARGT_STOP; arg_p++) {
				if (!lua_checkstack(stream->hlua->T, 1)) {
					SEND_ERR(stream->be, "Lua converter '%s': full stack.\n", fcn->name);
					RESET_SAFE_LJMP(stream->hlua);
					return 0;
				}
				hlua_arg2lua(stream->hlua->T, arg_p);
				stream->hlua->nargs++;
			}
		}

		/* We must initialize the execution timeouts. */
		stream->hlua->max_time = hlua_timeout_session;

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(stream->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(stream->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* If the stack is empty, the function fails. */
		if (lua_gettop(stream->hlua->T) <= 0)
			return 0;

		/* Convert the returned value in sample. */
		hlua_lua2smp(stream->hlua->T, -1, smp);
		lua_pop(stream->hlua->T, 1);
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		SEND_ERR(stream->be, "Lua converter '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		SEND_ERR(stream->be, "Lua converter '%s': %s.\n",
		         fcn->name, lua_tostring(stream->hlua->T, -1));
		lua_pop(stream->hlua->T, 1);
		return 0;

	case HLUA_E_ETMOUT:
		SEND_ERR(stream->be, "Lua converter '%s': execution timeout.\n", fcn->name);
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
		/* fall through */

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
	const char *error;
	unsigned int hflags = HLUA_TXN_NOTERM;

	if (!stream)
		return 0;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!stream->hlua) {
		stream->hlua = pool_alloc(pool_head_hlua);
		if (!stream->hlua) {
			SEND_ERR(stream->be, "Lua sample-fetch '%s': can't initialize Lua context.\n", fcn->name);
			return 0;
		}
		if (!hlua_ctx_init(stream->hlua, fcn_ref_to_stack_id(fcn), stream->task, 0)) {
			SEND_ERR(stream->be, "Lua sample-fetch '%s': can't initialize Lua context.\n", fcn->name);
			return 0;
		}
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(stream->hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(stream->hlua)) {
			if (lua_type(stream->hlua->T, -1) == LUA_TSTRING)
				error = lua_tostring(stream->hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(smp->px, "Lua sample-fetch '%s': %s.\n", fcn->name, error);
			return 0;
		}

		/* Check stack available size. */
		if (!lua_checkstack(stream->hlua->T, 2)) {
			SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(stream->hlua);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(stream->hlua->T, LUA_REGISTRYINDEX, fcn->function_ref[stream->hlua->state_id]);

		/* push arguments in the stack. */
		if (!hlua_txn_new(stream->hlua->T, stream, smp->px, smp->opt & SMP_OPT_DIR, hflags)) {
			SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
			RESET_SAFE_LJMP(stream->hlua);
			return 0;
		}
		stream->hlua->nargs = 1;

		/* push keywords in the stack. */
		for (; arg_p && arg_p->type != ARGT_STOP; arg_p++) {
			/* Check stack available size. */
			if (!lua_checkstack(stream->hlua->T, 1)) {
				SEND_ERR(smp->px, "Lua sample-fetch '%s': full stack.\n", fcn->name);
				RESET_SAFE_LJMP(stream->hlua);
				return 0;
			}
			hlua_arg2lua(stream->hlua->T, arg_p);
			stream->hlua->nargs++;
		}

		/* We must initialize the execution timeouts. */
		stream->hlua->max_time = hlua_timeout_session;

		/* At this point the execution is safe. */
		RESET_SAFE_LJMP(stream->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(stream->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* If the stack is empty, the function fails. */
		if (lua_gettop(stream->hlua->T) <= 0)
			return 0;

		/* Convert the returned value in sample. */
		hlua_lua2smp(stream->hlua->T, -1, smp);
		lua_pop(stream->hlua->T, 1);

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
		SEND_ERR(smp->px, "Lua sample-fetch '%s': %s.\n",
		         fcn->name, lua_tostring(stream->hlua->T, -1));
		lua_pop(stream->hlua->T, 1);
		return 0;

	case HLUA_E_ETMOUT:
		SEND_ERR(smp->px, "Lua sample-fetch '%s': execution timeout.\n", fcn->name);
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
		/* fall through */

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
	struct hlua_function *fcn;
	struct sample_conv *sc;
	struct buffer *trash;

	MAY_LJMP(check_args(L, 2, "register_converters"));

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
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	sck = calloc(1, sizeof(*sck) + sizeof(struct sample_conv) * 2);
	if (!sck)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn = new_hlua_function();
	if (!fcn)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	sck->list.n = sck->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sck->kw[0].kw = calloc(1, len);
	if (!sck->kw[0].kw)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

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
	struct hlua_function *fcn;
	struct sample_fetch *sf;
	struct buffer *trash;

	MAY_LJMP(check_args(L, 2, "register_fetches"));

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
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	sfk = calloc(1, sizeof(*sfk) + sizeof(struct sample_fetch) * 2);
	if (!sfk)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn = new_hlua_function();
	if (!fcn)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	sfk->list.n = sfk->list.p = NULL;

	/* sample-fetch keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sfk->kw[0].kw = calloc(1, len);
	if (!sfk->kw[0].kw)
		return luaL_error(L, "Lua out of memory error.");

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
}

/* This function is a lua binding to set the wake_time.
 */
__LJMP static int hlua_set_wake_time(lua_State *L)
{
	struct hlua *hlua;
	unsigned int delay;
	unsigned int wakeup_ms;

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
	unsigned int hflags = 0;
	int dir, act_ret = ACT_RET_CONT;
	const char *error;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CNT: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_RES_CNT: dir = SMP_OPT_DIR_RES; break;
	case ACT_F_HTTP_REQ:    dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_HTTP_RES:    dir = SMP_OPT_DIR_RES; break;
	default:
		SEND_ERR(px, "Lua: internal error while execute action.\n");
		goto end;
	}

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!s->hlua) {
		s->hlua = pool_alloc(pool_head_hlua);
		if (!s->hlua) {
			SEND_ERR(px, "Lua action '%s': can't initialize Lua context.\n",
			         rule->arg.hlua_rule->fcn->name);
			goto end;
		}
		if (!hlua_ctx_init(s->hlua, fcn_ref_to_stack_id(rule->arg.hlua_rule->fcn), s->task, 0)) {
			SEND_ERR(px, "Lua action '%s': can't initialize Lua context.\n",
			         rule->arg.hlua_rule->fcn->name);
			goto end;
		}
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(s->hlua)) {

		/* The following Lua calls can fail. */
		if (!SET_SAFE_LJMP(s->hlua)) {
			if (lua_type(s->hlua->T, -1) == LUA_TSTRING)
				error = lua_tostring(s->hlua->T, -1);
			else
				error = "critical error";
			SEND_ERR(px, "Lua function '%s': %s.\n",
			         rule->arg.hlua_rule->fcn->name, error);
			goto end;
		}

		/* Check stack available size. */
		if (!lua_checkstack(s->hlua->T, 1)) {
			SEND_ERR(px, "Lua function '%s': full stack.\n",
			         rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(s->hlua);
			goto end;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(s->hlua->T, LUA_REGISTRYINDEX, rule->arg.hlua_rule->fcn->function_ref[s->hlua->state_id]);

		/* Create and and push object stream in the stack. */
		if (!hlua_txn_new(s->hlua->T, s, px, dir, hflags)) {
			SEND_ERR(px, "Lua function '%s': full stack.\n",
			         rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(s->hlua);
			goto end;
		}
		s->hlua->nargs = 1;

		/* push keywords in the stack. */
		for (arg = rule->arg.hlua_rule->args; arg && *arg; arg++) {
			if (!lua_checkstack(s->hlua->T, 1)) {
				SEND_ERR(px, "Lua function '%s': full stack.\n",
				         rule->arg.hlua_rule->fcn->name);
				RESET_SAFE_LJMP(s->hlua);
				goto end;
			}
			lua_pushstring(s->hlua->T, *arg);
			s->hlua->nargs++;
		}

		/* Now the execution is safe. */
		RESET_SAFE_LJMP(s->hlua);

		/* We must initialize the execution timeouts. */
		s->hlua->max_time = hlua_timeout_session;
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(s->hlua, !(flags & ACT_OPT_FINAL))) {
	/* finished. */
	case HLUA_E_OK:
		/* Catch the return value */
		if (lua_gettop(s->hlua->T) > 0)
			act_ret = lua_tointeger(s->hlua->T, -1);

		/* Set timeout in the required channel. */
		if (act_ret == ACT_RET_YIELD) {
			if (flags & ACT_OPT_FINAL)
				goto err_yield;

			if (dir == SMP_OPT_DIR_REQ)
				s->req.analyse_exp = tick_first((tick_is_expired(s->req.analyse_exp, now_ms) ? 0 : s->req.analyse_exp),
								s->hlua->wake_time);
			else
				s->res.analyse_exp = tick_first((tick_is_expired(s->res.analyse_exp, now_ms) ? 0 : s->res.analyse_exp),
								s->hlua->wake_time);
		}
		goto end;

	/* yield. */
	case HLUA_E_AGAIN:
		/* Set timeout in the required channel. */
		if (dir == SMP_OPT_DIR_REQ)
			s->req.analyse_exp = tick_first((tick_is_expired(s->req.analyse_exp, now_ms) ? 0 : s->req.analyse_exp),
							s->hlua->wake_time);
		else
			s->res.analyse_exp = tick_first((tick_is_expired(s->res.analyse_exp, now_ms) ? 0 : s->res.analyse_exp),
							s->hlua->wake_time);

		/* Some actions can be wake up when a "write" event
		 * is detected on a response channel. This is useful
		 * only for actions targeted on the requests.
		 */
		if (HLUA_IS_WAKERESWR(s->hlua))
			s->res.flags |= CF_WAKE_WRITE;
		if (HLUA_IS_WAKEREQWR(s->hlua))
			s->req.flags |= CF_WAKE_WRITE;
		act_ret = ACT_RET_YIELD;
		goto end;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		SEND_ERR(px, "Lua function '%s': %s.\n",
		         rule->arg.hlua_rule->fcn->name, lua_tostring(s->hlua->T, -1));
		lua_pop(s->hlua->T, 1);
		goto end;

	case HLUA_E_ETMOUT:
		SEND_ERR(px, "Lua function '%s': execution timeout.\n", rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_NOMEM:
		SEND_ERR(px, "Lua function '%s': out of memory error.\n", rule->arg.hlua_rule->fcn->name);
		goto end;

	case HLUA_E_YIELD:
	  err_yield:
		act_ret = ACT_RET_CONT;
		SEND_ERR(px, "Lua function '%s': aborting Lua processing on expired timeout.\n",
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
	if (act_ret != ACT_RET_YIELD && s->hlua)
		s->hlua->wake_time = TICK_ETERNITY;
	return act_ret;
}

struct task *hlua_applet_wakeup(struct task *t, void *context, unsigned short state)
{
	struct appctx *ctx = context;

	appctx_wakeup(ctx);
	t->expire = TICK_ETERNITY;
	return t;
}

static int hlua_applet_tcp_init(struct appctx *ctx, struct proxy *px, struct stream *strm)
{
	struct stream_interface *si = ctx->owner;
	struct hlua *hlua;
	struct task *task;
	char **arg;
	const char *error;

	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(px, "Lua applet tcp '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}
	HLUA_INIT(hlua);
	ctx->ctx.hlua_apptcp.hlua = hlua;
	ctx->ctx.hlua_apptcp.flags = 0;

	/* Create task used by signal to wakeup applets. */
	task = task_new(tid_bit);
	if (!task) {
		SEND_ERR(px, "Lua applet tcp '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}
	task->nice = 0;
	task->context = ctx;
	task->process = hlua_applet_wakeup;
	ctx->ctx.hlua_apptcp.task = task;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(ctx->rule->arg.hlua_rule->fcn), task, 0)) {
		SEND_ERR(px, "Lua applet tcp '%s': can't initialize Lua context.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}

	/* Set timeout according with the applet configuration. */
	hlua->max_time = ctx->applet->timeout;

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = lua_tostring(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(px, "Lua applet tcp '%s': %s.\n",
		         ctx->rule->arg.hlua_rule->fcn->name, error);
		return 0;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 1)) {
		SEND_ERR(px, "Lua applet tcp '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return 0;
	}

	/* Restore the function in the stack. */
	lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, ctx->rule->arg.hlua_rule->fcn->function_ref[hlua->state_id]);

	/* Create and and push object stream in the stack. */
	if (!hlua_applet_tcp_new(hlua->T, ctx)) {
		SEND_ERR(px, "Lua applet tcp '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return 0;
	}
	hlua->nargs = 1;

	/* push keywords in the stack. */
	for (arg = ctx->rule->arg.hlua_rule->args; arg && *arg; arg++) {
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(px, "Lua applet tcp '%s': full stack.\n",
			         ctx->rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}
		lua_pushstring(hlua->T, *arg);
		hlua->nargs++;
	}

	RESET_SAFE_LJMP(hlua);

	/* Wakeup the applet ASAP. */
	si_cant_get(si);
	si_rx_endp_more(si);

	return 1;
}

void hlua_applet_tcp_fct(struct appctx *ctx)
{
	struct stream_interface *si = ctx->owner;
	struct stream *strm = si_strm(si);
	struct channel *res = si_ic(si);
	struct act_rule *rule = ctx->rule;
	struct proxy *px = strm->be;
	struct hlua *hlua = ctx->ctx.hlua_apptcp.hlua;

	/* The applet execution is already done. */
	if (ctx->ctx.hlua_apptcp.flags & APPLET_DONE) {
		/* eat the whole request */
		co_skip(si_oc(si), co_data(si_oc(si)));
		return;
	}

	/* If the stream is disconnect or closed, ldo nothing. */
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		return;

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 1)) {
	/* finished. */
	case HLUA_E_OK:
		ctx->ctx.hlua_apptcp.flags |= APPLET_DONE;

		/* eat the whole request */
		co_skip(si_oc(si), co_data(si_oc(si)));
		res->flags |= CF_READ_NULL;
		si_shutr(si);
		return;

	/* yield. */
	case HLUA_E_AGAIN:
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(ctx->ctx.hlua_apptcp.task, hlua->wake_time);
		return;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		SEND_ERR(px, "Lua applet tcp '%s': %s.\n",
		         rule->arg.hlua_rule->fcn->name, lua_tostring(hlua->T, -1));
		lua_pop(hlua->T, 1);
		goto error;

	case HLUA_E_ETMOUT:
		SEND_ERR(px, "Lua applet tcp '%s': execution timeout.\n",
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

error:

	/* For all other cases, just close the stream. */
	si_shutw(si);
	si_shutr(si);
	ctx->ctx.hlua_apptcp.flags |= APPLET_DONE;
}

static void hlua_applet_tcp_release(struct appctx *ctx)
{
	task_destroy(ctx->ctx.hlua_apptcp.task);
	ctx->ctx.hlua_apptcp.task = NULL;
	hlua_ctx_destroy(ctx->ctx.hlua_apptcp.hlua);
	ctx->ctx.hlua_apptcp.hlua = NULL;
}

/* The function returns 1 if the initialisation is complete, 0 if
 * an errors occurs and -1 if more data are required for initializing
 * the applet.
 */
static int hlua_applet_http_init(struct appctx *ctx, struct proxy *px, struct stream *strm)
{
	struct stream_interface *si = ctx->owner;
	struct http_txn *txn;
	struct hlua *hlua;
	char **arg;
	struct task *task;
	const char *error;

	txn = strm->txn;
	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(px, "Lua applet http '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}
	HLUA_INIT(hlua);
	ctx->ctx.hlua_apphttp.hlua = hlua;
	ctx->ctx.hlua_apphttp.left_bytes = -1;
	ctx->ctx.hlua_apphttp.flags = 0;

	if (txn->req.flags & HTTP_MSGF_VER_11)
		ctx->ctx.hlua_apphttp.flags |= APPLET_HTTP11;

	/* Create task used by signal to wakeup applets. */
	task = task_new(tid_bit);
	if (!task) {
		SEND_ERR(px, "Lua applet http '%s': out of memory.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}
	task->nice = 0;
	task->context = ctx;
	task->process = hlua_applet_wakeup;
	ctx->ctx.hlua_apphttp.task = task;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(ctx->rule->arg.hlua_rule->fcn), task, 0)) {
		SEND_ERR(px, "Lua applet http '%s': can't initialize Lua context.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		return 0;
	}

	/* Set timeout according with the applet configuration. */
	hlua->max_time = ctx->applet->timeout;

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = lua_tostring(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(px, "Lua applet http '%s': %s.\n",
		         ctx->rule->arg.hlua_rule->fcn->name, error);
		return 0;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 1)) {
		SEND_ERR(px, "Lua applet http '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return 0;
	}

	/* Restore the function in the stack. */
	lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, ctx->rule->arg.hlua_rule->fcn->function_ref[hlua->state_id]);

	/* Create and and push object stream in the stack. */
	if (!hlua_applet_http_new(hlua->T, ctx)) {
		SEND_ERR(px, "Lua applet http '%s': full stack.\n",
		         ctx->rule->arg.hlua_rule->fcn->name);
		RESET_SAFE_LJMP(hlua);
		return 0;
	}
	hlua->nargs = 1;

	/* push keywords in the stack. */
	for (arg = ctx->rule->arg.hlua_rule->args; arg && *arg; arg++) {
		if (!lua_checkstack(hlua->T, 1)) {
			SEND_ERR(px, "Lua applet http '%s': full stack.\n",
			         ctx->rule->arg.hlua_rule->fcn->name);
			RESET_SAFE_LJMP(hlua);
			return 0;
		}
		lua_pushstring(hlua->T, *arg);
		hlua->nargs++;
	}

	RESET_SAFE_LJMP(hlua);

	/* Wakeup the applet when data is ready for read. */
	si_cant_get(si);

	return 1;
}

void hlua_applet_http_fct(struct appctx *ctx)
{
	struct stream_interface *si = ctx->owner;
	struct stream *strm = si_strm(si);
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	struct act_rule *rule = ctx->rule;
	struct proxy *px = strm->be;
	struct hlua *hlua = ctx->ctx.hlua_apphttp.hlua;
	struct htx *req_htx, *res_htx;

	res_htx = htx_from_buf(&res->buf);

	/* If the stream is disconnect or closed, ldo nothing. */
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is available. */
	if (!b_size(&res->buf)) {
		si_rx_room_blk(si);
		goto out;
	}
	/* check that the output is not closed */
	if (res->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_SHUTR))
		ctx->ctx.hlua_apphttp.flags |= APPLET_DONE;

	/* Set the currently running flag. */
	if (!HLUA_IS_RUNNING(hlua) &&
	    !(ctx->ctx.hlua_apphttp.flags & APPLET_DONE)) {
		struct htx_blk *blk;
		size_t count = co_data(req);

		if (!count) {
			si_cant_get(si);
			goto out;
		}

		/* We need to flush the request header. This left the body for
		 * the Lua.
		 */
		req_htx = htx_from_buf(&req->buf);
		blk = htx_get_first_blk(req_htx);
		while (count && blk) {
			enum htx_blk_type type = htx_get_blk_type(blk);
			uint32_t sz = htx_get_blksz(blk);

			if (sz > count) {
				si_cant_get(si);
				htx_to_buf(req_htx, &req->buf);
				goto out;
			}

			count -= sz;
			co_set_data(req, co_data(req) - sz);
			blk = htx_remove_blk(req_htx, blk);

			if (type == HTX_BLK_EOH)
				break;
		}
		htx_to_buf(req_htx, &req->buf);
	}

	/* Executes The applet if it is not done. */
	if (!(ctx->ctx.hlua_apphttp.flags & APPLET_DONE)) {

		/* Execute the function. */
		switch (hlua_ctx_resume(hlua, 1)) {
		/* finished. */
		case HLUA_E_OK:
			ctx->ctx.hlua_apphttp.flags |= APPLET_DONE;
			break;

		/* yield. */
		case HLUA_E_AGAIN:
			if (hlua->wake_time != TICK_ETERNITY)
				task_schedule(ctx->ctx.hlua_apphttp.task, hlua->wake_time);
			goto out;

		/* finished with error. */
		case HLUA_E_ERRMSG:
			/* Display log. */
			SEND_ERR(px, "Lua applet http '%s': %s.\n",
			         rule->arg.hlua_rule->fcn->name, lua_tostring(hlua->T, -1));
			lua_pop(hlua->T, 1);
			goto error;

		case HLUA_E_ETMOUT:
			SEND_ERR(px, "Lua applet http '%s': execution timeout.\n",
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
	}

	if (ctx->ctx.hlua_apphttp.flags & APPLET_DONE) {
		if (ctx->ctx.hlua_apphttp.flags & APPLET_RSP_SENT)
			goto done;

		if (!(ctx->ctx.hlua_apphttp.flags & APPLET_HDR_SENT))
			goto error;

		/* Don't add TLR because mux-h1 will take care of it */
		res_htx->flags |= HTX_FL_EOI; /* no more data are expected. Only EOM remains to add now */
		if (!htx_add_endof(res_htx, HTX_BLK_EOM)) {
			si_rx_room_blk(si);
			goto out;
		}
		channel_add_input(res, 1);
		strm->txn->status = ctx->ctx.hlua_apphttp.status;
		ctx->ctx.hlua_apphttp.flags |= APPLET_RSP_SENT;
	}

  done:
	if (ctx->ctx.hlua_apphttp.flags & APPLET_DONE) {
		if (!(res->flags & CF_SHUTR)) {
			res->flags |= CF_READ_NULL;
			si_shutr(si);
		}

		/* eat the whole request */
		if (co_data(req)) {
			req_htx = htx_from_buf(&req->buf);
			co_htx_skip(req, req_htx, co_data(req));
			htx_to_buf(req_htx, &req->buf);
		}
	}

  out:
	htx_to_buf(res_htx, &res->buf);
	return;

  error:

	/* If we are in HTTP mode, and we are not send any
	 * data, return a 500 server error in best effort:
	 * if there is no room available in the buffer,
	 * just close the connection.
	 */
	if (!(ctx->ctx.hlua_apphttp.flags & APPLET_HDR_SENT)) {
		struct buffer *err = &http_err_chunks[HTTP_ERR_500];

		channel_erase(res);
		res->buf.data = b_data(err);
                memcpy(res->buf.area, b_head(err), b_data(err));
                res_htx = htx_from_buf(&res->buf);
		channel_add_input(res, res_htx->data);
	}
	if (!(strm->flags & SF_ERR_MASK))
		strm->flags |= SF_ERR_RESOURCE;
	ctx->ctx.hlua_apphttp.flags |= APPLET_DONE;
	goto done;
}

static void hlua_applet_http_release(struct appctx *ctx)
{
	task_destroy(ctx->ctx.hlua_apphttp.task);
	ctx->ctx.hlua_apphttp.task = NULL;
	hlua_ctx_destroy(ctx->ctx.hlua_apphttp.hlua);
	ctx->ctx.hlua_apphttp.hlua = NULL;
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
		return ACT_RET_PRS_ERR;
	}

	/* Memory for arguments. */
	rule->arg.hlua_rule->args = calloc(fcn->nargs + 1,
					   sizeof(*rule->arg.hlua_rule->args));
	if (!rule->arg.hlua_rule->args) {
		memprintf(err, "out of memory error");
		return ACT_RET_PRS_ERR;
	}

	/* Reference the Lua function and store the reference. */
	rule->arg.hlua_rule->fcn = fcn;

	/* Expect some arguments */
	for (i = 0; i < fcn->nargs; i++) {
		if (*args[*cur_arg] == '\0') {
			memprintf(err, "expect %d arguments", fcn->nargs);
			return ACT_RET_PRS_ERR;
		}
		rule->arg.hlua_rule->args[i] = strdup(args[*cur_arg]);
		if (!rule->arg.hlua_rule->args[i]) {
			memprintf(err, "out of memory error");
			return ACT_RET_PRS_ERR;
		}
		(*cur_arg)++;
	}
	rule->arg.hlua_rule->args[i] = NULL;

	rule->action = ACT_CUSTOM;
	rule->action_ptr = hlua_action;
	return ACT_RET_PRS_OK;
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
	struct action_kw_list *akl;
	const char *name;
	int ref;
	int len;
	struct hlua_function *fcn;
	int nargs;
	struct buffer *trash;
	struct action_kw *akw;

	/* Initialise the number of expected arguments at 0. */
	nargs = 0;

	if (lua_gettop(L) < 3 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'register_action' needs between 3 and 4 arguments"));

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
		if (lua_type(L, -1) != LUA_TSTRING)
			WILL_LJMP(luaL_error(L, "register_action: second argument must be a table of strings"));

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
		} else {
			akw = NULL;
		}
		if (akw != NULL) {
			fcn = akw->private;
			if (fcn->function_ref[hlua_state_id] != -1) {
				ha_warning("Trying to register action 'lua.%s' more than once. "
				           "This will become a hard error in version 2.5.\n", name);
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
			WILL_LJMP(luaL_error(L, "Lua out of memory error."));
		fcn = new_hlua_function();
		if (!fcn)
			WILL_LJMP(luaL_error(L, "Lua out of memory error."));

		/* Fill fcn. */
		fcn->name = strdup(name);
		if (!fcn->name)
			WILL_LJMP(luaL_error(L, "Lua out of memory error."));
		fcn->function_ref[hlua_state_id] = ref;

		/* Set the expected number od arguments. */
		fcn->nargs = nargs;

		/* List head */
		akl->list.n = akl->list.p = NULL;

		/* action keyword. */
		len = strlen("lua.") + strlen(name) + 1;
		akl->kw[0].kw = calloc(1, len);
		if (!akl->kw[0].kw)
			WILL_LJMP(luaL_error(L, "Lua out of memory error."));

		snprintf((char *)akl->kw[0].kw, len, "lua.%s", name);

		akl->kw[0].match_pfx = 0;
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
		else
			WILL_LJMP(luaL_error(L, "Lua action environment '%s' is unknown. "
			                        "'tcp-req', 'tcp-res', 'http-req' or 'http-res' "
			                        "are expected.", lua_tostring(L, -1)));

		/* pop the environment string. */
		lua_pop(L, 1);
	}
	return ACT_RET_PRS_OK;
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
	struct hlua_function *fcn;
	struct buffer *trash;
	struct action_kw *akw;

	MAY_LJMP(check_args(L, 3, "register_service"));

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
		}
		fcn->function_ref[hlua_state_id] = ref;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	akl = calloc(1, sizeof(*akl) + sizeof(struct action_kw) * 2);
	if (!akl)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn = new_hlua_function();
	if (!fcn)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Fill fcn. */
	len = strlen("<lua.>") + strlen(name) + 1;
	fcn->name = calloc(1, len);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	snprintf((char *)fcn->name, len, "<lua.%s>", name);
	fcn->function_ref[hlua_state_id] = ref;

	/* List head */
	akl->list.n = akl->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	akl->kw[0].kw = calloc(1, len);
	if (!akl->kw[0].kw)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	snprintf((char *)akl->kw[0].kw, len, "lua.%s", name);

	/* Check required environment. Only accepted "http" or "tcp". */
	if (strcmp(env, "tcp") == 0)
		akl->kw[0].parse = action_register_service_tcp;
	else if (strcmp(env, "http") == 0)
		akl->kw[0].parse = action_register_service_http;
	else
		WILL_LJMP(luaL_error(L, "Lua service environment '%s' is unknown. "
		                        "'tcp' or 'http' are expected.", env));

	akl->kw[0].match_pfx = 0;
	akl->kw[0].private = fcn;

	/* End of array. */
	memset(&akl->kw[1], 0, sizeof(*akl->kw));

	/* Register this new converter */
	service_keywords_register(akl);

	return 0;
}

/* This function initialises Lua cli handler. It copies the
 * arguments in the Lua stack and create channel IO objects.
 */
static int hlua_cli_parse_fct(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct hlua *hlua;
	struct hlua_function *fcn;
	int i;
	const char *error;

	fcn = private;
	appctx->ctx.hlua_cli.fcn = private;

	hlua = pool_alloc(pool_head_hlua);
	if (!hlua) {
		SEND_ERR(NULL, "Lua cli '%s': out of memory.\n", fcn->name);
		return 1;
	}
	HLUA_INIT(hlua);
	appctx->ctx.hlua_cli.hlua = hlua;

	/* Create task used by signal to wakeup applets.
	 * We use the same wakeup function than the Lua applet_tcp and
	 * applet_http. It is absolutely compatible.
	 */
	appctx->ctx.hlua_cli.task = task_new(tid_bit);
	if (!appctx->ctx.hlua_cli.task) {
		SEND_ERR(NULL, "Lua cli '%s': out of memory.\n", fcn->name);
		goto error;
	}
	appctx->ctx.hlua_cli.task->nice = 0;
	appctx->ctx.hlua_cli.task->context = appctx;
	appctx->ctx.hlua_cli.task->process = hlua_applet_wakeup;

	/* Initialises the Lua context */
	if (!hlua_ctx_init(hlua, fcn_ref_to_stack_id(fcn), appctx->ctx.hlua_cli.task, 0)) {
		SEND_ERR(NULL, "Lua cli '%s': can't initialize Lua context.\n", fcn->name);
		goto error;
	}

	/* The following Lua calls can fail. */
	if (!SET_SAFE_LJMP(hlua)) {
		if (lua_type(hlua->T, -1) == LUA_TSTRING)
			error = lua_tostring(hlua->T, -1);
		else
			error = "critical error";
		SEND_ERR(NULL, "Lua cli '%s': %s.\n", fcn->name, error);
		goto error;
	}

	/* Check stack available size. */
	if (!lua_checkstack(hlua->T, 2)) {
		SEND_ERR(NULL, "Lua cli '%s': full stack.\n", fcn->name);
		goto error;
	}

	/* Restore the function in the stack. */
	lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, fcn->function_ref[hlua->state_id]);

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
	hlua->max_time = hlua_timeout_session;

	/* At this point the execution is safe. */
	RESET_SAFE_LJMP(hlua);

	/* It's ok */
	return 0;

	/* It's not ok. */
error:
	RESET_SAFE_LJMP(hlua);
	hlua_ctx_destroy(hlua);
	appctx->ctx.hlua_cli.hlua = NULL;
	return 1;
}

static int hlua_cli_io_handler_fct(struct appctx *appctx)
{
	struct hlua *hlua;
	struct stream_interface *si;
	struct hlua_function *fcn;

	hlua = appctx->ctx.hlua_cli.hlua;
	si = appctx->owner;
	fcn = appctx->ctx.hlua_cli.fcn;

	/* If the stream is disconnect or closed, ldo nothing. */
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		return 1;

	/* Execute the function. */
	switch (hlua_ctx_resume(hlua, 1)) {

	/* finished. */
	case HLUA_E_OK:
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		/* We want write. */
		if (HLUA_IS_WAKERESWR(hlua))
			si_rx_room_blk(si);
		/* Set the timeout. */
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(hlua->task, hlua->wake_time);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		SEND_ERR(NULL, "Lua cli '%s': %s.\n",
		         fcn->name, lua_tostring(hlua->T, -1));
		lua_pop(hlua->T, 1);
		return 1;

	case HLUA_E_ETMOUT:
		SEND_ERR(NULL, "Lua converter '%s': execution timeout.\n",
		         fcn->name);
		return 1;

	case HLUA_E_NOMEM:
		SEND_ERR(NULL, "Lua converter '%s': out of memory error.\n",
		         fcn->name);
		return 1;

	case HLUA_E_YIELD: /* unexpected */
		SEND_ERR(NULL, "Lua converter '%s': yield not allowed.\n",
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
	hlua_ctx_destroy(appctx->ctx.hlua_cli.hlua);
	appctx->ctx.hlua_cli.hlua = NULL;
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
	struct hlua_function *fcn;
	int index;
	int i;
	struct buffer *trash;
	const char *kw[5];
	struct cli_kw *cli_kw;

	MAY_LJMP(check_args(L, 3, "register_cli"));

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
		if (index >= CLI_PREFIX_KW_NB)
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table with a maximum of 5 entries"));
		if (lua_type(L, -1) != LUA_TSTRING)
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table filled with strings"));
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
		}
		fcn->function_ref[hlua_state_id] = ref_io;
		return 0;
	}

	/* Allocate and fill the sample fetch keyword struct. */
	cli_kws = calloc(1, sizeof(*cli_kws) + sizeof(struct cli_kw) * 2);
	if (!cli_kws)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	fcn = new_hlua_function();
	if (!fcn)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Fill path. */
	index = 0;
	lua_pushnil(L);
	while(lua_next(L, 1) != 0) {
		if (index >= 5)
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table with a maximum of 5 entries"));
		if (lua_type(L, -1) != LUA_TSTRING)
			WILL_LJMP(luaL_argerror(L, 1, "1st argument must be a table filled with strings"));
		cli_kws->kw[0].str_kw[index] = strdup(lua_tostring(L, -1));
		if (!cli_kws->kw[0].str_kw[index])
			WILL_LJMP(luaL_error(L, "Lua out of memory error."));
		index++;
		lua_pop(L, 1);
	}

	/* Copy help message. */
	cli_kws->kw[0].usage = strdup(message);
	if (!cli_kws->kw[0].usage)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));

	/* Fill fcn io handler. */
	len = strlen("<lua.cli>") + 1;
	for (i = 0; i < index; i++)
		len += strlen(cli_kws->kw[0].str_kw[i]) + 1;
	fcn->name = calloc(1, len);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "Lua out of memory error."));
	strncat((char *)fcn->name, "<lua.cli", len);
	for (i = 0; i < index; i++) {
		strncat((char *)fcn->name, ".", len);
		strncat((char *)fcn->name, cli_kws->kw[0].str_kw[i], len);
	}
	strncat((char *)fcn->name, ">", len);
	fcn->function_ref[hlua_state_id] = ref_io;

	/* Fill last entries. */
	cli_kws->kw[0].private = fcn;
	cli_kws->kw[0].parse = hlua_cli_parse_fct;
	cli_kws->kw[0].io_handler = hlua_cli_io_handler_fct;
	cli_kws->kw[0].io_release = hlua_cli_io_release_fct;

	/* Register this new converter */
	cli_register_kw(cli_kws);

	return 0;
}

static int hlua_read_timeout(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
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

static int hlua_session_timeout(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_session);
}

static int hlua_task_timeout(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_task);
}

static int hlua_applet_timeout(char **args, int section_type, struct proxy *curpx,
                               struct proxy *defpx, const char *file, int line,
                               char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_applet);
}

static int hlua_forced_yield(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
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
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	char *error;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument (Lua memory size in MB).\n", args[0]);
		return -1;
	}
	hlua_global_allocator.limit = strtoll(args[1], &error, 10) * 1024L * 1024L;
	if (*error != '\0') {
		memprintf(err, "%s: invalid number %s (error at '%c')", args[0], args[1], *error);
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
static int hlua_load_state(char *filename, lua_State *L, char **err)
{
	int error;

	/* Just load and compile the file. */
	error = luaL_loadfile(L, filename);
	if (error) {
		memprintf(err, "error in Lua file '%s': %s", filename, lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
	}

	/* If no syntax error where detected, execute the code. */
	error = lua_pcall(L, 0, LUA_MULTRET, 0);
	switch (error) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		memprintf(err, "Lua runtime error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
	case LUA_ERRMEM:
		memprintf(err, "Lua out of memory error\n");
		return -1;
	case LUA_ERRERR:
		memprintf(err, "Lua message handler error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 503
	case LUA_ERRGCMM:
		memprintf(err, "Lua garbage collector error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
#endif
	default:
		memprintf(err, "Lua unknown error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
	}

	return 0;
}

static int hlua_load(char **args, int section_type, struct proxy *curpx,
                     struct proxy *defpx, const char *file, int line,
                     char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file name as parameter.\n", args[0]);
		return -1;
	}

	/* loading for global state */
	hlua_state_id = 0;
	ha_set_tid(0);
	return hlua_load_state(args[1], hlua_states[0], err);
}

static int hlua_load_per_thread(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	int len;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file as parameter.\n", args[0]);
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

	per_thread_load[len]     = strdup(args[1]);
	per_thread_load[len + 1] = NULL;

	if (per_thread_load[len] == NULL) {
		memprintf(err, "out of memory error");
		return -1;
	}

	/* loading for thread 1 only */
	hlua_state_id = 1;
	ha_set_tid(0);
	return hlua_load_state(args[1], hlua_states[1], err);
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
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	char *path;
	char *type = "path";
	struct prepend_path *p = NULL;

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
	LIST_ADDQ(&prepend_path_list, &p->l);

	hlua_prepend_path(hlua_states[0], type, path);
	hlua_prepend_path(hlua_states[1], type, path);
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
	{ CFG_GLOBAL, "tune.lua.forced-yield",    hlua_forced_yield },
	{ CFG_GLOBAL, "tune.lua.maxmem",          hlua_parse_maxmem },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);


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
			error = lua_tostring(L, -1);
		else
			error = "critical error";
		fprintf(stderr, "Lua post-init: %s.\n", error);
		exit(1);
	} else {
		lua_atpanic(L, hlua_panic_ljmp);
	}

	hlua_fcn_post_init(L);

	list_for_each_entry(init, &hlua_init_functions[hlua_state_id], l) {
		lua_rawgeti(L, LUA_REGISTRYINDEX, init->function_ref);

#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
		ret = lua_resume(L, L, 0, &nres);
#else
		ret = lua_resume(L, L, 0);
#endif
		kind = NULL;
		switch (ret) {

		case LUA_OK:
			lua_pop(L, -1);
			break;

		case LUA_ERRERR:
			kind = "message handler error";
			/* Fall thru */
		case LUA_ERRRUN:
			if (!kind)
				kind = "runtime error";
			msg = lua_tostring(L, -1);
			lua_settop(L, 0); /* Empty the stack. */
			lua_pop(L, 1);
			trace = hlua_traceback(L);
			if (msg)
				ha_alert("Lua init: %s: '%s' from %s\n", kind, msg, trace);
			else
				ha_alert("Lua init: unknown %s from %s\n", kind, trace);
			return_status = 0;
			break;

		default:
			/* Unknown error */
			kind = "Unknown error";
			/* Fall thru */
		case LUA_YIELD:
			/* yield is not configured at this step, this state doesn't happen */
			if (!kind)
				kind = "yield not allowed";
			/* Fall thru */
		case LUA_ERRMEM:
			if (!kind)
				kind = "out of memory error";
			lua_settop(L, 0);
			lua_pop(L, 1);
			trace = hlua_traceback(L);
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

#if USE_OPENSSL
	/* Initialize SSL server. */
	if (socket_ssl.xprt->prepare_srv) {
		int saved_used_backed = global.ssl_used_backend;
		// don't affect maxconn automatic computation
		socket_ssl.xprt->prepare_srv(&socket_ssl);
		global.ssl_used_backend = saved_used_backed;
	}
#endif

	/* Perform post init of common thread */
	hlua_state_id = 0;
	ha_set_tid(0);
	ret = hlua_post_init_state(hlua_states[hlua_state_id]);
	if (ret == 0)
		return 0;

	/* init remaining lua states and load files */
	for (hlua_state_id = 2; hlua_state_id < global.nbthread + 1; hlua_state_id++) {

		/* set thread context */
		ha_set_tid(hlua_state_id - 1);

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
	ha_set_tid(0);

	/* Execute post init for all states */
	for (hlua_state_id = 1; hlua_state_id < global.nbthread + 1; hlua_state_id++) {

		/* set thread context */
		ha_set_tid(hlua_state_id - 1);

		/* run post init */
		ret = hlua_post_init_state(hlua_states[hlua_state_id]);
		if (ret == 0)
			return 0;
	}

	/* Reset thread context */
	ha_set_tid(0);

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
 */
static void *hlua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct hlua_mem_allocator *zone = ud;
	size_t limit, old, new;

	/* a limit of ~0 means unlimited and boot complete, so there's no need
	 * for accounting anymore.
	 */
	if (likely(~zone->limit == 0))
		return realloc(ptr, nsize);

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
			error_msg = lua_tostring(L, -1);
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
	 *
	 * Create "core" object.
	 *
	 */

	/* This table entry is the object "core" base. */
	lua_newtable(L);

	/* set the thread id */
	hlua_class_const_int(L, "thread", thread_num);

	/* Push the loglevel constants. */
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
	hlua_class_function(L, "yield", hlua_yield);
	hlua_class_function(L, "set_nice", hlua_set_nice);
	hlua_class_function(L, "sleep", hlua_sleep);
	hlua_class_function(L, "msleep", hlua_msleep);
	hlua_class_function(L, "add_acl", hlua_add_acl);
	hlua_class_function(L, "del_acl", hlua_del_acl);
	hlua_class_function(L, "set_map", hlua_set_map);
	hlua_class_function(L, "del_map", hlua_del_map);
	hlua_class_function(L, "tcp", hlua_socket_new);
	hlua_class_function(L, "log", hlua_log);
	hlua_class_function(L, "Debug", hlua_log_debug);
	hlua_class_function(L, "Info", hlua_log_info);
	hlua_class_function(L, "Warning", hlua_log_warning);
	hlua_class_function(L, "Alert", hlua_log_alert);
	hlua_class_function(L, "done", hlua_done);
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
	 * Register class Channel
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(L);

	/* Create and fill the __index entry. */
	lua_pushstring(L, "__index");
	lua_newtable(L);

	/* Register . */
	hlua_class_function(L, "get",         hlua_channel_get);
	hlua_class_function(L, "dup",         hlua_channel_dup);
	hlua_class_function(L, "getline",     hlua_channel_getline);
	hlua_class_function(L, "set",         hlua_channel_set);
	hlua_class_function(L, "append",      hlua_channel_append);
	hlua_class_function(L, "send",        hlua_channel_send);
	hlua_class_function(L, "forward",     hlua_channel_forward);
	hlua_class_function(L, "get_in_len",  hlua_channel_get_in_len);
	hlua_class_function(L, "get_out_len", hlua_channel_get_out_len);
	hlua_class_function(L, "is_full",     hlua_channel_is_full);
	hlua_class_function(L, "is_resp",     hlua_channel_is_resp);

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
		strncpy(trash.area, sf->kw, trash.size);
		trash.area[trash.size - 1] = '\0';
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
		strncpy(trash.area, sc->kw, trash.size);
		trash.area[trash.size - 1] = '\0';
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
	hlua_class_function(L, "set_loglevel",        hlua_txn_set_loglevel);
	hlua_class_function(L, "set_tos",             hlua_txn_set_tos);
	hlua_class_function(L, "set_mark",            hlua_txn_set_mark);
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
	int idx;
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
	ha_set_tid(0);
	hlua_states[0] = hlua_init_state(0);

	/* Init state 1 for thread 0. We have at least one thread. */
	hlua_state_id = 1;
	ha_set_tid(0);
	hlua_states[1] = hlua_init_state(1);

	/* Proxy and server configuration initialisation. */
	memset(&socket_proxy, 0, sizeof(socket_proxy));
	init_new_proxy(&socket_proxy);
	socket_proxy.parent = NULL;
	socket_proxy.last_change = now.tv_sec;
	socket_proxy.id = "LUA-SOCKET";
	socket_proxy.cap = PR_CAP_FE | PR_CAP_BE;
	socket_proxy.maxconn = 0;
	socket_proxy.accept = NULL;
	socket_proxy.options2 |= PR_O2_INDEPSTR;
	socket_proxy.srv = NULL;
	socket_proxy.conn_retries = 0;
	socket_proxy.timeout.connect = 5000; /* By default the timeout connection is 5s. */

	/* Init TCP server: unchanged parameters */
	memset(&socket_tcp, 0, sizeof(socket_tcp));
	socket_tcp.next = NULL;
	socket_tcp.proxy = &socket_proxy;
	socket_tcp.obj_type = OBJ_TYPE_SERVER;
	LIST_INIT(&socket_tcp.actconns);
	socket_tcp.pendconns = EB_ROOT;
	socket_tcp.idle_conns = NULL;
	socket_tcp.safe_conns = NULL;
	socket_tcp.next_state = SRV_ST_RUNNING; /* early server setup */
	socket_tcp.last_change = 0;
	socket_tcp.id = "LUA-TCP-CONN";
	socket_tcp.check.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_tcp.agent.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_tcp.pp_opts = 0; /* Remove proxy protocol. */

	/* XXX: Copy default parameter from default server,
	 * but the default server is not initialized.
	 */
	socket_tcp.maxqueue     = socket_proxy.defsrv.maxqueue;
	socket_tcp.minconn      = socket_proxy.defsrv.minconn;
	socket_tcp.maxconn      = socket_proxy.defsrv.maxconn;
	socket_tcp.slowstart    = socket_proxy.defsrv.slowstart;
	socket_tcp.onerror      = socket_proxy.defsrv.onerror;
	socket_tcp.onmarkeddown = socket_proxy.defsrv.onmarkeddown;
	socket_tcp.onmarkedup   = socket_proxy.defsrv.onmarkedup;
	socket_tcp.consecutive_errors_limit = socket_proxy.defsrv.consecutive_errors_limit;
	socket_tcp.uweight      = socket_proxy.defsrv.iweight;
	socket_tcp.iweight      = socket_proxy.defsrv.iweight;

	socket_tcp.check.status = HCHK_STATUS_INI;
	socket_tcp.check.rise   = socket_proxy.defsrv.check.rise;
	socket_tcp.check.fall   = socket_proxy.defsrv.check.fall;
	socket_tcp.check.health = socket_tcp.check.rise;   /* socket, but will fall down at first failure */
	socket_tcp.check.server = &socket_tcp;

	socket_tcp.agent.status = HCHK_STATUS_INI;
	socket_tcp.agent.rise   = socket_proxy.defsrv.agent.rise;
	socket_tcp.agent.fall   = socket_proxy.defsrv.agent.fall;
	socket_tcp.agent.health = socket_tcp.agent.rise;   /* socket, but will fall down at first failure */
	socket_tcp.agent.server = &socket_tcp;

	socket_tcp.xprt = xprt_get(XPRT_RAW);

#ifdef USE_OPENSSL
	/* Init TCP server: unchanged parameters */
	memset(&socket_ssl, 0, sizeof(socket_ssl));
	socket_ssl.next = NULL;
	socket_ssl.proxy = &socket_proxy;
	socket_ssl.obj_type = OBJ_TYPE_SERVER;
	LIST_INIT(&socket_ssl.actconns);
	socket_ssl.pendconns = EB_ROOT;
	socket_ssl.idle_conns = NULL;
	socket_ssl.safe_conns = NULL;
	socket_ssl.next_state = SRV_ST_RUNNING; /* early server setup */
	socket_ssl.last_change = 0;
	socket_ssl.id = "LUA-SSL-CONN";
	socket_ssl.check.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_ssl.agent.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_ssl.pp_opts = 0; /* Remove proxy protocol. */

	/* XXX: Copy default parameter from default server,
	 * but the default server is not initialized.
	 */
	socket_ssl.maxqueue     = socket_proxy.defsrv.maxqueue;
	socket_ssl.minconn      = socket_proxy.defsrv.minconn;
	socket_ssl.maxconn      = socket_proxy.defsrv.maxconn;
	socket_ssl.slowstart    = socket_proxy.defsrv.slowstart;
	socket_ssl.onerror      = socket_proxy.defsrv.onerror;
	socket_ssl.onmarkeddown = socket_proxy.defsrv.onmarkeddown;
	socket_ssl.onmarkedup   = socket_proxy.defsrv.onmarkedup;
	socket_ssl.consecutive_errors_limit = socket_proxy.defsrv.consecutive_errors_limit;
	socket_ssl.uweight      = socket_proxy.defsrv.iweight;
	socket_ssl.iweight      = socket_proxy.defsrv.iweight;

	socket_ssl.check.status = HCHK_STATUS_INI;
	socket_ssl.check.rise   = socket_proxy.defsrv.check.rise;
	socket_ssl.check.fall   = socket_proxy.defsrv.check.fall;
	socket_ssl.check.health = socket_ssl.check.rise;   /* socket, but will fall down at first failure */
	socket_ssl.check.server = &socket_ssl;

	socket_ssl.agent.status = HCHK_STATUS_INI;
	socket_ssl.agent.rise   = socket_proxy.defsrv.agent.rise;
	socket_ssl.agent.fall   = socket_proxy.defsrv.agent.fall;
	socket_ssl.agent.health = socket_ssl.agent.rise;   /* socket, but will fall down at first failure */
	socket_ssl.agent.server = &socket_ssl;

	socket_ssl.use_ssl = 1;
	socket_ssl.xprt = xprt_get(XPRT_SSL);

	for (idx = 0; args[idx] != NULL; idx++) {
		if ((kw = srv_find_kw(args[idx])) != NULL) { /* Maybe it's registered server keyword */
			/*
			 *
			 * If the keyword is not known, we can search in the registered
			 * server keywords. This is useful to configure special SSL
			 * features like client certificates and ssl_verify.
			 *
			 */
			tmp_error = kw->parse(args, &idx, &socket_proxy, &socket_ssl, &error);
			if (tmp_error != 0) {
				fprintf(stderr, "INTERNAL ERROR: %s\n", error);
				abort(); /* This must be never arrives because the command line
				            not editable by the user. */
			}
			idx += kw->skip;
		}
	}
#endif

}

static void hlua_deinit()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS+1; thr++) {
		if (hlua_states[thr])
			lua_close(hlua_states[thr]);
	}
}

REGISTER_POST_DEINIT(hlua_deinit);

static void hlua_register_build_options(void)
{
	char *ptr = NULL;

	memprintf(&ptr, "Built with Lua version : %s", LUA_RELEASE);
	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, hlua_register_build_options);
