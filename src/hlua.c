#include <sys/socket.h>

#include <ctype.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
#error "Requires Lua 5.3 or later."
#endif

#include <ebpttree.h>

#include <common/cfgparse.h>

#include <types/connection.h>
#include <types/hlua.h>
#include <types/proto_tcp.h>
#include <types/proxy.h>

#include <proto/arg.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/map.h>
#include <proto/obj_type.h>
#include <proto/pattern.h>
#include <proto/payload.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/raw_sock.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/vars.h>

/* Lua uses longjmp to perform yield or throwing errors. This
 * macro is used only for identifying the function that can
 * not return because a longjmp is executed.
 *   __LJMP marks a prototype of hlua file that can use longjmp.
 *   WILL_LJMP() marks an lua function that will use longjmp.
 *   MAY_LJMP() marks an lua function that may use longjmp.
 */
#define __LJMP
#define WILL_LJMP(func) func
#define MAY_LJMP(func) func

/* The main Lua execution context. */
struct hlua gL;

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each requiered signal between two tasks.
 */
struct pool_head *pool2_hlua_com;

/* Used for Socket connection. */
static struct proxy socket_proxy;
static struct server socket_tcp;
#ifdef USE_OPENSSL
static struct server socket_ssl;
#endif

/* List head of the function called at the initialisation time. */
struct list hlua_init_functions = LIST_HEAD_INIT(hlua_init_functions);

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

/* Global Lua execution timeout. By default Lua, execution linked
 * with stream (actions, sample-fetches and converters) have a
 * short timeout. Lua linked with tasks doesn't have a timeout
 * because a task may remain alive during all the haproxy execution.
 */
static unsigned int hlua_timeout_session = 4000; /* session timeout. */
static unsigned int hlua_timeout_task = TICK_ETERNITY; /* task timeout. */

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

/* Descriptor for the memory allocation state. If limit is not null, it will
 * be enforced on any memory allocation.
 */
struct hlua_mem_allocator {
	size_t allocated;
	size_t limit;
};

static struct hlua_mem_allocator hlua_global_allocator;

/* These functions converts types between HAProxy internal args or
 * sample and LUA types. Another function permits to check if the
 * LUA stack contains arguments according with an required ARG_T
 * format.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg);
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg);
__LJMP static int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                                     unsigned int mask, struct proxy *p);
static int hlua_smp2lua(lua_State *L, struct sample *smp);
static int hlua_smp2lua_str(lua_State *L, struct sample *smp);
static int hlua_lua2smp(lua_State *L, int ud, struct sample *smp);

/* Used to check an Lua function type in the stack. It creates and
 * returns a reference of the function. This function throws an
 * error if the rgument is not a "function".
 */
__LJMP unsigned int hlua_checkfunction(lua_State *L, int argno)
{
	if (!lua_isfunction(L, argno)) {
		const char *msg = lua_pushfstring(L, "function expected, got %s", luaL_typename(L, -1));
		WILL_LJMP(luaL_argerror(L, argno, msg));
	}
	lua_pushvalue(L, argno);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* The three following functions are useful for adding entries
 * in a table. These functions takes a string and respectively an
 * integer, a string or a function and add it to the table in the
 * top of the stack.
 *
 * These functions throws an error if no more stack size is
 * available.
 */
__LJMP static inline void hlua_class_const_int(lua_State *L, const char *name,
                                               int value)
{
	if (!lua_checkstack(L, 2))
	WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushinteger(L, value);
	lua_settable(L, -3);
}
__LJMP static inline void hlua_class_const_str(lua_State *L, const char *name,
                                        const char *value)
{
	if (!lua_checkstack(L, 2))
		WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushstring(L, value);
	lua_settable(L, -3);
}
__LJMP static inline void hlua_class_function(lua_State *L, const char *name,
                                       int (*function)(lua_State *L))
{
	if (!lua_checkstack(L, 2))
		WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_settable(L, -3);
}

/* This function check the number of arguments available in the
 * stack. If the number of arguments available is not the same
 * then <nb> an error is throwed.
 */
__LJMP static inline void check_args(lua_State *L, int nb, char *fcn)
{
	if (lua_gettop(L) == nb)
		return;
	WILL_LJMP(luaL_error(L, "'%s' needs %d arguments", fcn, nb));
}

/* Return true if the data in stack[<ud>] is an object of
 * type <class_ref>.
 */
static int hlua_metaistype(lua_State *L, int ud, int class_ref)
{
	if (!lua_getmetatable(L, ud))
		return 0;

	lua_rawgeti(L, LUA_REGISTRYINDEX, class_ref);
	if (!lua_rawequal(L, -1, -2)) {
		lua_pop(L, 2);
		return 0;
	}

	lua_pop(L, 2);
	return 1;
}

/* Return an object of the expected type, or throws an error. */
__LJMP static void *hlua_checkudata(lua_State *L, int ud, int class_ref)
{
	void *p;

	/* Check if the stack entry is an array. */
	if (!lua_istable(L, ud))
		WILL_LJMP(luaL_argerror(L, ud, NULL));
	/* Check if the metadata have the expected type. */
	if (!hlua_metaistype(L, ud, class_ref))
		WILL_LJMP(luaL_argerror(L, ud, NULL));
	/* Push on the stack at the entry [0] of the table. */
	lua_rawgeti(L, ud, 0);
	/* Check if this entry is userdata. */
	p = lua_touserdata(L, -1);
	if (!p)
		WILL_LJMP(luaL_argerror(L, ud, NULL));
	/* Remove the entry returned by lua_rawgeti(). */
	lua_pop(L, 1);
	/* Return the associated struct. */
	return p;
}

/* This fucntion push an error string prefixed by the file name
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

/* This function register a new signal. "lua" is the current lua
 * execution context. It contains a pointer to the associated task.
 * "link" is a list head attached to an other task that must be wake
 * the lua task if an event occurs. This is useful with external
 * events like TCP I/O or sleep functions. This funcion allocate
 * memory for the signal.
 */
static int hlua_com_new(struct hlua *lua, struct list *link)
{
	struct hlua_com *com = pool_alloc2(pool2_hlua_com);
	if (!com)
		return 0;
	LIST_ADDQ(&lua->com, &com->purge_me);
	LIST_ADDQ(link, &com->wake_me);
	com->task = lua->task;
	return 1;
}

/* This function purge all the pending signals when the LUA execution
 * is finished. This prevent than a coprocess try to wake a deleted
 * task. This function remove the memory associated to the signal.
 */
static void hlua_com_purge(struct hlua *lua)
{
	struct hlua_com *com, *back;

	/* Delete all pending communication signals. */
	list_for_each_entry_safe(com, back, &lua->com, purge_me) {
		LIST_DEL(&com->purge_me);
		LIST_DEL(&com->wake_me);
		pool_free2(pool2_hlua_com, com);
	}
}

/* This function sends signals. It wakes all the tasks attached
 * to a list head, and remove the signal, and free the used
 * memory.
 */
static void hlua_com_wake(struct list *wake)
{
	struct hlua_com *com, *back;

	/* Wake task and delete all pending communication signals. */
	list_for_each_entry_safe(com, back, wake, wake_me) {
		LIST_DEL(&com->purge_me);
		LIST_DEL(&com->wake_me);
		task_wakeup(com->task, TASK_WOKEN_MSG);
		pool_free2(pool2_hlua_com, com);
	}
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
		lua_pushinteger(L, arg->data.sint);
		break;

	case ARGT_UINT:
	case ARGT_TIME:
	case ARGT_SIZE:
		lua_pushinteger(L, arg->data.sint);
		break;

	case ARGT_STR:
		lua_pushlstring(L, arg->data.str.str, arg->data.str.len);
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

/* This function take one entrie in an LUA stack at the index "ud",
 * and try to convert it in an HAProxy argument entry. This is useful
 * with sample fetch wrappers. The input arguments are gived to the
 * lua wrapper and converted as arg list by thi function.
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
		arg->data.str.str = (char *)lua_tolstring(L, ud, (size_t *)&arg->data.str.len);
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
		arg->type = ARGT_SINT;
		arg->data.uint = 0;
		break;
	}
	return 1;
}

/* the following functions are used to convert a struct sample
 * in Lua type. This useful to convert the return of the
 * fetchs or converters.
 */
static int hlua_smp2lua(lua_State *L, struct sample *smp)
{
	switch (smp->type) {
	case SMP_T_SINT:
	case SMP_T_BOOL:
	case SMP_T_UINT:
		lua_pushinteger(L, smp->data.sint);
		break;

	case SMP_T_BIN:
	case SMP_T_STR:
		lua_pushlstring(L, smp->data.str.str, smp->data.str.len);
		break;

	case SMP_T_METH:
		switch (smp->data.meth.meth) {
		case HTTP_METH_OPTIONS: lua_pushstring(L, "OPTIONS"); break;
		case HTTP_METH_GET:     lua_pushstring(L, "GET");     break;
		case HTTP_METH_HEAD:    lua_pushstring(L, "HEAD");    break;
		case HTTP_METH_POST:    lua_pushstring(L, "POST");    break;
		case HTTP_METH_PUT:     lua_pushstring(L, "PUT");     break;
		case HTTP_METH_DELETE:  lua_pushstring(L, "DELETE");  break;
		case HTTP_METH_TRACE:   lua_pushstring(L, "TRACE");   break;
		case HTTP_METH_CONNECT: lua_pushstring(L, "CONNECT"); break;
		case HTTP_METH_OTHER:
			lua_pushlstring(L, smp->data.meth.str.str, smp->data.meth.str.len);
			break;
		default:
			lua_pushnil(L);
			break;
		}
		break;

	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_ADDR: /* This type is never used to qualify a sample. */
		if (sample_casts[smp->type][SMP_T_STR] &&
		    sample_casts[smp->type][SMP_T_STR](smp))
			lua_pushlstring(L, smp->data.str.str, smp->data.str.len);
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
 * fetchs or converters.
 */
static int hlua_smp2lua_str(lua_State *L, struct sample *smp)
{
	switch (smp->type) {

	case SMP_T_BIN:
	case SMP_T_STR:
		lua_pushlstring(L, smp->data.str.str, smp->data.str.len);
		break;

	case SMP_T_METH:
		switch (smp->data.meth.meth) {
		case HTTP_METH_OPTIONS: lua_pushstring(L, "OPTIONS"); break;
		case HTTP_METH_GET:     lua_pushstring(L, "GET");     break;
		case HTTP_METH_HEAD:    lua_pushstring(L, "HEAD");    break;
		case HTTP_METH_POST:    lua_pushstring(L, "POST");    break;
		case HTTP_METH_PUT:     lua_pushstring(L, "PUT");     break;
		case HTTP_METH_DELETE:  lua_pushstring(L, "DELETE");  break;
		case HTTP_METH_TRACE:   lua_pushstring(L, "TRACE");   break;
		case HTTP_METH_CONNECT: lua_pushstring(L, "CONNECT"); break;
		case HTTP_METH_OTHER:
			lua_pushlstring(L, smp->data.meth.str.str, smp->data.meth.str.len);
			break;
		default:
			lua_pushstring(L, "");
			break;
		}
		break;

	case SMP_T_SINT:
	case SMP_T_BOOL:
	case SMP_T_UINT:
	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_ADDR: /* This type is never used to qualify a sample. */
		if (sample_casts[smp->type][SMP_T_STR] &&
		    sample_casts[smp->type][SMP_T_STR](smp))
			lua_pushlstring(L, smp->data.str.str, smp->data.str.len);
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
		smp->type = SMP_T_SINT;
		smp->data.sint = lua_tointeger(L, ud);
		break;


	case LUA_TBOOLEAN:
		smp->type = SMP_T_BOOL;
		smp->data.uint = lua_toboolean(L, ud);
		break;

	case LUA_TSTRING:
		smp->type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->data.str.str = (char *)lua_tolstring(L, ud, (size_t *)&smp->data.str.len);
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
		smp->type = SMP_T_BOOL;
		smp->data.uint = 0;
		break;
	}
	return 1;
}

/* This function check the "argp" builded by another conversion function
 * is in accord with the expected argp defined by the "mask". The fucntion
 * returns true or false. It can be adjust the types if there compatibles.
 *
 * This function assumes thant the argp argument contains ARGM_NBARGS + 1
 * entries.
 */
__LJMP int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp,
                              unsigned int mask, struct proxy *p)
{
	int min_arg;
	int idx;
	struct proxy *px;
	char *sname, *pname;

	idx = 0;
	min_arg = ARGM(mask);
	mask >>= ARGM_BITS;

	while (1) {

		/* Check oversize. */
		if (idx >= ARGM_NBARGS && argp[idx].type != ARGT_STOP) {
			WILL_LJMP(luaL_argerror(L, first + idx, "Malformed argument mask"));
		}

		/* Check for mandatory arguments. */
		if (argp[idx].type == ARGT_STOP) {
			if (idx < min_arg) {

				/* If miss other argument than the first one, we return an error. */
				if (idx > 0)
					WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));

				/* If first argument have a certain type, some default values
				 * may be used. See the function smp_resolve_args().
				 */
				switch (mask & ARGT_MASK) {

				case ARGT_FE:
					if (!(p->cap & PR_CAP_FE))
						WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));
					argp[idx].data.prx = p;
					argp[idx].type = ARGT_FE;
					argp[idx+1].type = ARGT_STOP;
					break;

				case ARGT_BE:
					if (!(p->cap & PR_CAP_BE))
						WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));
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
					WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));
					break;
				}
			}
			return 0;
		}

		/* Check for exceed the number of requiered argument. */
		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type != ARGT_STOP) {
			WILL_LJMP(luaL_argerror(L, first + idx, "Last argument expected"));
		}

		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type == ARGT_STOP) {
			return 0;
		}

		/* Convert some argument types. */
		switch (mask & ARGT_MASK) {
		case ARGT_SINT:
			if (argp[idx].type != ARGT_SINT)
				WILL_LJMP(luaL_argerror(L, first + idx, "integer expected"));
			argp[idx].type = ARGT_SINT;
			break;

		case ARGT_UINT:
			if (argp[idx].type != ARGT_SINT)
				WILL_LJMP(luaL_argerror(L, first + idx, "integer expected"));
			argp[idx].type = ARGT_SINT;
			break;

		case ARGT_TIME:
			if (argp[idx].type != ARGT_SINT)
				WILL_LJMP(luaL_argerror(L, first + idx, "integer expected"));
			argp[idx].type = ARGT_TIME;
			break;

		case ARGT_SIZE:
			if (argp[idx].type != ARGT_SINT)
				WILL_LJMP(luaL_argerror(L, first + idx, "integer expected"));
			argp[idx].type = ARGT_SIZE;
			break;

		case ARGT_FE:
			if (argp[idx].type != ARGT_STR)
				WILL_LJMP(luaL_argerror(L, first + idx, "string expected"));
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			argp[idx].data.prx = proxy_fe_by_name(trash.str);
			if (!argp[idx].data.prx)
				WILL_LJMP(luaL_argerror(L, first + idx, "frontend doesn't exist"));
			argp[idx].type = ARGT_FE;
			break;

		case ARGT_BE:
			if (argp[idx].type != ARGT_STR)
				WILL_LJMP(luaL_argerror(L, first + idx, "string expected"));
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			argp[idx].data.prx = proxy_be_by_name(trash.str);
			if (!argp[idx].data.prx)
				WILL_LJMP(luaL_argerror(L, first + idx, "backend doesn't exist"));
			argp[idx].type = ARGT_BE;
			break;

		case ARGT_TAB:
			if (argp[idx].type != ARGT_STR)
				WILL_LJMP(luaL_argerror(L, first + idx, "string expected"));
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			argp[idx].data.prx = proxy_tbl_by_name(trash.str);
			if (!argp[idx].data.prx)
				WILL_LJMP(luaL_argerror(L, first + idx, "table doesn't exist"));
			argp[idx].type = ARGT_TAB;
			break;

		case ARGT_SRV:
			if (argp[idx].type != ARGT_STR)
				WILL_LJMP(luaL_argerror(L, first + idx, "string expected"));
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			sname = strrchr(trash.str, '/');
			if (sname) {
				*sname++ = '\0';
				pname = trash.str;
				px = proxy_be_by_name(pname);
				if (!px)
					WILL_LJMP(luaL_argerror(L, first + idx, "backend doesn't exist"));
			}
			else {
				sname = trash.str;
				px = p;
			}
			argp[idx].data.srv = findserver(px, sname);
			if (!argp[idx].data.srv)
				WILL_LJMP(luaL_argerror(L, first + idx, "server doesn't exist"));
			argp[idx].type = ARGT_SRV;
			break;

		case ARGT_IPV4:
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			if (inet_pton(AF_INET, trash.str, &argp[idx].data.ipv4))
				WILL_LJMP(luaL_argerror(L, first + idx, "invalid IPv4 address"));
			argp[idx].type = ARGT_IPV4;
			break;

		case ARGT_MSK4:
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			if (!str2mask(trash.str, &argp[idx].data.ipv4))
				WILL_LJMP(luaL_argerror(L, first + idx, "invalid IPv4 mask"));
			argp[idx].type = ARGT_MSK4;
			break;

		case ARGT_IPV6:
			memcpy(trash.str, argp[idx].data.str.str, argp[idx].data.str.len);
			trash.str[argp[idx].data.str.len] = 0;
			if (inet_pton(AF_INET6, trash.str, &argp[idx].data.ipv6))
				WILL_LJMP(luaL_argerror(L, first + idx, "invalid IPv6 address"));
			argp[idx].type = ARGT_IPV6;
			break;

		case ARGT_MSK6:
		case ARGT_MAP:
		case ARGT_REG:
		case ARGT_USR:
			WILL_LJMP(luaL_argerror(L, first + idx, "type not yet supported"));
			break;
		}

		/* Check for type of argument. */
		if ((mask & ARGT_MASK) != argp[idx].type) {
			const char *msg = lua_pushfstring(L, "'%s' expected, got '%s'",
			                                  arg_type_names[(mask & ARGT_MASK)],
			                                  arg_type_names[argp[idx].type & ARGT_MASK]);
			WILL_LJMP(luaL_argerror(L, first + idx, msg));
		}

		/* Next argument. */
		mask >>= ARGT_BITS;
		idx++;
	}
}

/*
 * The following functions are used to make correspondance between the the
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
	p = trash.str;
	for (; *msg != '\0'; msg++, p++) {
		if (p >= trash.str + trash.size - 1)
			return;
		if (isprint(*msg))
			*p = *msg;
		else
			*p = '.';
	}
	*p = '\0';

	send_log(px, level, "%s", trash.str);
	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
      get_localtime(date.tv_sec, &tm);
      fprintf(stderr, "[%s] %03d/%02d%02d%02d (%d) : %s\n",
		        log_levels[level], tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec,
		        (int)getpid(), trash.str);
		fflush(stderr);
	}
}

/* This function just ensure that the yield will be always
 * returned with a timeout and permit to set some flags
 */
__LJMP void hlua_yieldk(lua_State *L, int nresults, int ctx,
                        lua_KFunction k, int timeout, unsigned int flags)
{
	struct hlua *hlua = hlua_gethlua(L);

	/* Set the wake timeout. If timeout is required, we set
	 * the expiration time.
	 */
	hlua->wake_time = tick_first(timeout, hlua->expire);

	hlua->flags |= flags;

	/* Process the yield. */
	WILL_LJMP(lua_yieldk(L, nresults, ctx, k));
}

/* This function initialises the Lua environment stored in the stream.
 * It must be called at the start of the stream. This function creates
 * an LUA coroutine. It can not be use to crete the main LUA context.
 */
int hlua_ctx_init(struct hlua *lua, struct task *task)
{
	lua->Mref = LUA_REFNIL;
	lua->flags = 0;
	LIST_INIT(&lua->com);
	lua->T = lua_newthread(gL.T);
	if (!lua->T) {
		lua->Tref = LUA_REFNIL;
		return 0;
	}
	hlua_sethlua(lua);
	lua->Tref = luaL_ref(gL.T, LUA_REGISTRYINDEX);
	lua->task = task;
	return 1;
}

/* Used to destroy the Lua coroutine when the attached stream or task
 * is destroyed. The destroy also the memory context. The struct "lua"
 * is not freed.
 */
void hlua_ctx_destroy(struct hlua *lua)
{
	if (!lua->T)
		return;

	/* Purge all the pending signals. */
	hlua_com_purge(lua);

	/* The thread is garbage collected by Lua. */
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	luaL_unref(gL.T, LUA_REGISTRYINDEX, lua->Tref);
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

	/* Renew the main LUA stack doesn't have sense. */
	if (lua == &gL)
		return 0;

	/* New Lua coroutine. */
	T = lua_newthread(gL.T);
	if (!T)
		return 0;

	/* Copy last error message. */
	if (keep_msg)
		lua_xmove(lua->T, T, 1);

	/* Copy data between the coroutines. */
	lua_rawgeti(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	lua_xmove(lua->T, T, 1);
	new_ref = luaL_ref(T, LUA_REGISTRYINDEX); /* Valur poped. */

	/* Destroy old data. */
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);

	/* The thread is garbage collected by Lua. */
	luaL_unref(gL.T, LUA_REGISTRYINDEX, lua->Tref);

	/* Fill the struct with the new coroutine values. */
	lua->Mref = new_ref;
	lua->T = T;
	lua->Tref = luaL_ref(gL.T, LUA_REGISTRYINDEX);

	/* Set context. */
	hlua_sethlua(lua);

	return 1;
}

void hlua_hook(lua_State *L, lua_Debug *ar)
{
	struct hlua *hlua = hlua_gethlua(L);

	/* Lua cannot yield when its returning from a function,
	 * so, we can fix the interrupt hook to 1 instruction,
	 * expecting that the function is finnished.
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
		WILL_LJMP(hlua_yieldk(L, 0, 0, NULL, TICK_ETERNITY, HLUA_CTRLYIELD));

	/* If we cannot yield, update the clock and check the timeout. */
	tv_update_date(0, 1);
	if (tick_is_expired(hlua->expire, now_ms)) {
		lua_pushfstring(L, "execution timeout");
		WILL_LJMP(lua_error(L));
	}

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
 *  - HLUA_E_ERRMSG : An error has occured, an error message is set in
 *                    the top of the stack.
 *  - HLUA_E_ERR    : An error has occured without error message.
 *
 * If an error occured, the stack is renewed and it is ready to run new
 * LUA code.
 */
static enum hlua_exec hlua_ctx_resume(struct hlua *lua, int yield_allowed)
{
	int ret;
	const char *msg;

	HLUA_SET_RUN(lua);

	/* If we want to resume the task, then check first the execution timeout.
	 * if it is reached, we can interrupt the Lua processing.
	 */
	if (tick_is_expired(lua->expire, now_ms))
		goto timeout_reached;

resume_execution:

	/* This hook interrupts the Lua processing each 'hlua_nb_instruction'
	 * instructions. it is used for preventing infinite loops.
	 */
	lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, hlua_nb_instruction);

	/* Remove all flags except the running flags. */
	lua->flags = HLUA_RUN;

	/* Call the function. */
	ret = lua_resume(lua->T, gL.T, lua->nargs);
	switch (ret) {

	case LUA_OK:
		ret = HLUA_E_OK;
		break;

	case LUA_YIELD:
		/* Check if the execution timeout is expired. It it is the case, we
		 * break the Lua execution.
		 */
		if (tick_is_expired(lua->expire, now_ms)) {

timeout_reached:

			lua_settop(lua->T, 0); /* Empty the stack. */
			if (!lua_checkstack(lua->T, 1)) {
				ret = HLUA_E_ERR;
				break;
			}
			lua_pushfstring(lua->T, "execution timeout");
			ret = HLUA_E_ERRMSG;
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
			if (!lua_checkstack(lua->T, 1)) {
				ret = HLUA_E_ERR;
				break;
			}
			lua_pushfstring(lua->T, "yield not allowed");
			ret = HLUA_E_ERRMSG;
			break;
		}
		ret = HLUA_E_AGAIN;
		break;

	case LUA_ERRRUN:
		lua->wake_time = TICK_ETERNITY;
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		msg = lua_tostring(lua->T, -1);
		lua_settop(lua->T, 0); /* Empty the stack. */
		lua_pop(lua->T, 1);
		if (msg)
			lua_pushfstring(lua->T, "runtime error: %s", msg);
		else
			lua_pushfstring(lua->T, "unknown runtime error");
		ret = HLUA_E_ERRMSG;
		break;

	case LUA_ERRMEM:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		lua_pushfstring(lua->T, "out of memory error");
		ret = HLUA_E_ERRMSG;
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
			lua_pushfstring(lua->T, "message handler error: %s", msg);
		else
			lua_pushfstring(lua->T, "message handler error");
		ret = HLUA_E_ERRMSG;
		break;

	default:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		lua_pushfstring(lua->T, "unknonwn error");
		ret = HLUA_E_ERRMSG;
		break;
	}

	switch (ret) {
	case HLUA_E_AGAIN:
		break;

	case HLUA_E_ERRMSG:
		hlua_com_purge(lua);
		hlua_ctx_renew(lua, 1);
		HLUA_CLR_RUN(lua);
		break;

	case HLUA_E_ERR:
		HLUA_CLR_RUN(lua);
		hlua_com_purge(lua);
		hlua_ctx_renew(lua, 0);
		break;

	case HLUA_E_OK:
		HLUA_CLR_RUN(lua);
		hlua_com_purge(lua);
		break;
	}

	return ret;
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
		WILL_LJMP(luaL_error(L, "'del_acl': unkown acl file '%s'", name));

	pat_ref_delete(ref, key);
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
		WILL_LJMP(luaL_error(L, "'del_map': unkown acl file '%s'", name));

	pat_ref_delete(ref, key);
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
		WILL_LJMP(luaL_error(L, "'add_acl': unkown acl file '%s'", name));

	if (pat_ref_find_elt(ref, key) == NULL)
		pat_ref_add(ref, key, NULL, NULL);
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
		WILL_LJMP(luaL_error(L, "'set_map': unkown map file '%s'", name));

	if (pat_ref_find_elt(ref, key) != NULL)
		pat_ref_set(ref, key, value, NULL);
	else
		pat_ref_add(ref, key, value, NULL);
	return 0;
}

/* A class is a lot of memory that contain data. This data can be a table,
 * an integer or user data. This data is associated with a metatable. This
 * metatable have an original version registred in the global context with
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
 * Special methods for redfining standar relations
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
	return (struct map_descriptor *)MAY_LJMP(hlua_checkudata(L, ud, class_map_ref));
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
	case PAT_MATCH_INT: conv.in_type = SMP_T_UINT; break;
	case PAT_MATCH_IP:  conv.in_type = SMP_T_ADDR; break;
	default:
		WILL_LJMP(luaL_error(L, "'new' doesn't support this match mode."));
	}

	/* fill fake args. */
	args[0].type = ARGT_STR;
	args[0].data.str.str = (char *)fn;
	args[1].type = ARGT_STOP;

	/* load the map. */
	if (!sample_load_map(args, &conv, file, line, &err)) {
		/* error case: we cant use luaL_error because we must
		 * free the err variable.
		 */
		luaL_where(L, 1);
		lua_pushfstring(L, "'new': %s.", err);
		lua_concat(L, 2);
		free(err);
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
	if (desc->pat.expect_type == SMP_T_UINT) {
		smp.type = SMP_T_UINT;
		smp.data.uint = MAY_LJMP(luaL_checkinteger(L, 2));
	}
	else {
		smp.type = SMP_T_STR;
		smp.flags = SMP_F_CONST;
		smp.data.str.str = (char *)MAY_LJMP(luaL_checklstring(L, 2, (size_t *)&smp.data.str.len));
	}

	pat = pattern_exec_match(&desc->pat, &smp, 1);
	if (!pat || !pat->smp) {
		if (str)
			lua_pushstring(L, "");
		else
			lua_pushnil(L);
		return 1;
	}

	/* The Lua pattern must return a string, so we can't check the returned type */
	lua_pushlstring(L, pat->smp->data.str.str, pat->smp->data.str.len);
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
	return (struct hlua_socket *)MAY_LJMP(hlua_checkudata(L, ud, class_socket_ref));
}

/* This function is the handler called for each I/O on the established
 * connection. It is used for notify space avalaible to send or data
 * received.
 */
static void hlua_socket_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct connection *c = objt_conn(si_opposite(si)->end);

	/* Wakeup the main stream if the client connection is closed. */
	if (!c || channel_output_closed(si_ic(si)) || channel_input_closed(si_oc(si))) {
		if (appctx->ctx.hlua.socket) {
			appctx->ctx.hlua.socket->s = NULL;
			appctx->ctx.hlua.socket = NULL;
		}
		si_shutw(si);
		si_shutr(si);
		si_ic(si)->flags |= CF_READ_NULL;
		hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
		hlua_com_wake(&appctx->ctx.hlua.wake_on_write);
		return;
	}

	if (!(c->flags & CO_FL_CONNECTED))
		return;

	/* This function is called after the connect. */
	appctx->ctx.hlua.connected = 1;

	/* Wake the tasks which wants to write if the buffer have avalaible space. */
	if (channel_may_recv(si_oc(si)))
		hlua_com_wake(&appctx->ctx.hlua.wake_on_write);

	/* Wake the tasks which wants to read if the buffer contains data. */
	if (channel_is_empty(si_ic(si)))
		hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
}

/* This function is called when the "struct stream" is destroyed.
 * Remove the link from the object to this stream.
 * Wake all the pending signals.
 */
static void hlua_socket_release(struct appctx *appctx)
{
	/* Remove my link in the original object. */
	if (appctx->ctx.hlua.socket)
		appctx->ctx.hlua.socket->s = NULL;

	/* Wake all the task waiting for me. */
	hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
	hlua_com_wake(&appctx->ctx.hlua.wake_on_write);
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

	MAY_LJMP(check_args(L, 1, "__gc"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	if (!socket->s)
		return 0;

	/* Remove all reference between the Lua stack and the coroutine stream. */
	appctx = objt_appctx(socket->s->si[0].end);
	stream_shutdown(socket->s, SF_ERR_KILLED);
	socket->s = NULL;
	appctx->ctx.hlua.socket = NULL;

	return 0;
}

/* The close function send shutdown signal and break the
 * links between the stream and the object.
 */
__LJMP static int hlua_socket_close(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;

	MAY_LJMP(check_args(L, 1, "close"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	if (!socket->s)
		return 0;

	/* Close the stream and remove the associated stop task. */
	stream_shutdown(socket->s, SF_ERR_KILLED);
	appctx = objt_appctx(socket->s->si[0].end);
	appctx->ctx.hlua.socket = NULL;
	socket->s = NULL;

	return 0;
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
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;
	int len;
	int nblk;
	char *blk1;
	int len1;
	char *blk2;
	int len2;
	int skip_at_end = 0;
	struct channel *oc;

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'receive' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* check for connection closed. If some data where read, return it. */
	if (!socket->s)
		goto connection_closed;

	oc = &socket->s->res;
	if (wanted == HLSR_READ_LINE) {
		/* Read line. */
		nblk = bo_getline_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
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
		nblk = bo_getblk_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
			goto connection_empty;
	}

	else {
		/* Read a block of data. */
		nblk = bo_getblk_nc(oc, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
			goto connection_empty;

		if (len1 > wanted) {
			nblk = 1;
			len1 = wanted;
		} if (nblk == 2 && len1 + len2 > wanted)
			len2 = wanted - len1;
	}

	len = len1;

	luaL_addlstring(&socket->b, blk1, len1);
	if (nblk == 2) {
		len += len2;
		luaL_addlstring(&socket->b, blk2, len2);
	}

	/* Consume data. */
	bo_skip(oc, len + skip_at_end);

	/* Don't wait anything. */
	si_applet_done(&socket->s->si[0]);

	/* If the pattern reclaim to read all the data
	 * in the connection, got out.
	 */
	if (wanted == HLSR_READ_ALL)
		goto connection_empty;
	else if (wanted >= 0 && len < wanted)
		goto connection_empty;

	/* Return result. */
	luaL_pushresult(&socket->b);
	return 1;

connection_closed:

	/* If the buffer containds data. */
	if (socket->b.n > 0) {
		luaL_pushresult(&socket->b);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, "connection closed.");
	return 2;

connection_empty:

	appctx = objt_appctx(socket->s->si[0].end);
	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_read))
		WILL_LJMP(luaL_error(L, "out of memory"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_receive_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This Lus function gets two parameters. The first one can be string
 * or a number. If the string is "*l", the user require one line. If
 * the string is "*a", the user require all the content of the stream.
 * If the value is a number, the user require a number of bytes equal
 * to the value. The default value is "*l" (a line).
 *
 * This paraeter with a variable type is converted in integer. This
 * integer takes this values:
 *  -1 : read a line
 *  -2 : read all the stream
 *  >0 : amount if bytes.
 *
 * The second parameter is optinal. It contains a string that must be
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
	lua_replace(L, 2);

	/* init bufffer, and fiil it wih prefix. */
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
 * This fucntion returns a yield if no space are available.
 */
static int hlua_socket_write_yield(struct lua_State *L,int status, lua_KContext ctx)
{
	struct hlua_socket *socket;
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;
	size_t buf_len;
	const char *buf;
	int len;
	int send_len;
	int sent;

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'write' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* Get object */
	socket = MAY_LJMP(hlua_checksocket(L, 1));
	buf = MAY_LJMP(luaL_checklstring(L, 2, &buf_len));
	sent = MAY_LJMP(luaL_checkinteger(L, 3));

	/* Check for connection close. */
	if (!socket->s || channel_output_closed(&socket->s->req)) {
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Update the input buffer data. */
	buf += sent;
	send_len = buf_len - sent;

	/* All the data are sent. */
	if (sent >= buf_len)
		return 1; /* Implicitly return the length sent. */

	/* Check if the buffer is avalaible because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (socket->s->req.buf->size == 0) {
		if (!stream_alloc_recv_buffer(&socket->s->req)) {
			socket->s->si[0].flags |= SI_FL_WAIT_ROOM;
			goto hlua_socket_write_yield_return;
		}
	}

	/* Check for avalaible space. */
	len = buffer_total_space(socket->s->req.buf);
	if (len <= 0)
		goto hlua_socket_write_yield_return;

	/* send data */
	if (len < send_len)
		send_len = len;
	len = bi_putblk(&socket->s->req, buf+sent, send_len);

	/* "Not enough space" (-1), "Buffer too little to contain
	 * the data" (-2) are not expected because the available length
	 * is tested.
	 * Other unknown error are also not expected.
	 */
	if (len <= 0) {
		if (len == -1)
			socket->s->req.flags |= CF_WAKE_WRITE;

		MAY_LJMP(hlua_socket_close(L));
		lua_pop(L, 1);
		lua_pushinteger(L, -1);
		return 1;
	}

	/* update buffers. */
	si_applet_done(&socket->s->si[0]);
	socket->s->req.rex = TICK_ETERNITY;
	socket->s->res.wex = TICK_ETERNITY;

	/* Update length sent. */
	lua_pop(L, 1);
	lua_pushinteger(L, sent + len);

	/* All the data buffer is sent ? */
	if (sent + len >= buf_len)
		return 1;

hlua_socket_write_yield_return:
	appctx = objt_appctx(socket->s->si[0].end);
	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_write))
		WILL_LJMP(luaL_error(L, "out of memory"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_write_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function initiate the send of data. It just check the input
 * parameters and push an integer in the Lua stack that contain the
 * amount of data writed in the buffer. This is used by the function
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
	struct connection *conn;

	MAY_LJMP(check_args(L, 1, "getpeername"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if the tcp object is avalaible. */
	if (!socket->s) {
		lua_pushnil(L);
		return 1;
	}

	conn = objt_conn(socket->s->si[1].end);
	if (!conn) {
		lua_pushnil(L);
		return 1;
	}

	if (!(conn->flags & CO_FL_ADDR_TO_SET)) {
		unsigned int salen = sizeof(conn->addr.to);
		if (getpeername(conn->t.sock.fd, (struct sockaddr *)&conn->addr.to, &salen) == -1) {
			lua_pushnil(L);
			return 1;
		}
		conn->flags |= CO_FL_ADDR_TO_SET;
	}

	return MAY_LJMP(hlua_socket_info(L, &conn->addr.to));
}

/* Returns information about my connection side. */
static int hlua_socket_getsockname(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct connection *conn;

	MAY_LJMP(check_args(L, 1, "getsockname"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if the tcp object is avalaible. */
	if (!socket->s) {
		lua_pushnil(L);
		return 1;
	}

	conn = objt_conn(socket->s->si[1].end);
	if (!conn) {
		lua_pushnil(L);
		return 1;
	}

	if (!(conn->flags & CO_FL_ADDR_FROM_SET)) {
		unsigned int salen = sizeof(conn->addr.from);
		if (getsockname(conn->t.sock.fd, (struct sockaddr *)&conn->addr.from, &salen) == -1) {
			lua_pushnil(L);
			return 1;
		}
		conn->flags |= CO_FL_ADDR_FROM_SET;
	}

	return hlua_socket_info(L, &conn->addr.from);
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
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;

	/* Check for connection close. */
	if (!hlua || !socket->s || channel_output_closed(&socket->s->req)) {
		lua_pushnil(L);
		lua_pushstring(L, "Can't connect");
		return 2;
	}

	appctx = objt_appctx(socket->s->si[0].end);

	/* Check for connection established. */
	if (appctx->ctx.hlua.connected) {
		lua_pushinteger(L, 1);
		return 1;
	}

	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_write))
		WILL_LJMP(luaL_error(L, "out of memory error"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function fail or initite the connection. */
__LJMP static int hlua_socket_connect(struct lua_State *L)
{
	struct hlua_socket *socket;
	int port;
	const char *ip;
	struct connection *conn;
	struct hlua *hlua;
	struct appctx *appctx;

	MAY_LJMP(check_args(L, 3, "connect"));

	/* Get args. */
	socket  = MAY_LJMP(hlua_checksocket(L, 1));
	ip      = MAY_LJMP(luaL_checkstring(L, 2));
	port    = MAY_LJMP(luaL_checkinteger(L, 3));

	conn = si_alloc_conn(&socket->s->si[1], 0);
	if (!conn)
		WILL_LJMP(luaL_error(L, "connect: internal error"));

	/* Parse ip address. */
	conn->addr.to.ss_family = AF_UNSPEC;
	if (!str2ip2(ip, &conn->addr.to, 0))
		WILL_LJMP(luaL_error(L, "connect: cannot parse ip address '%s'", ip));

	/* Set port. */
	if (conn->addr.to.ss_family == AF_INET)
		((struct sockaddr_in *)&conn->addr.to)->sin_port = htons(port);
	else if (conn->addr.to.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_port = htons(port);

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks.
	 */
	task_wakeup(socket->s->task, TASK_WOKEN_INIT);

	hlua = hlua_gethlua(L);
	appctx = objt_appctx(socket->s->si[0].end);
	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_write))
		WILL_LJMP(luaL_error(L, "out of memory"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));

	return 0;
}

#ifdef USE_OPENSSL
__LJMP static int hlua_socket_connect_ssl(struct lua_State *L)
{
	struct hlua_socket *socket;

	MAY_LJMP(check_args(L, 3, "connect_ssl"));
	socket  = MAY_LJMP(hlua_checksocket(L, 1));
	socket->s->target = &socket_ssl.obj_type;
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

	MAY_LJMP(check_args(L, 2, "settimeout"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	tmout = MAY_LJMP(luaL_checkinteger(L, 2)) * 1000;

	socket->s->req.rto = tmout;
	socket->s->req.wto = tmout;
	socket->s->res.rto = tmout;
	socket->s->res.wto = tmout;

	return 0;
}

__LJMP static int hlua_socket_new(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;
	struct session *sess;
	struct stream *strm;
	struct task *task;

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

	/* Check if the various memory pools are intialized. */
	if (!pool2_stream || !pool2_buffer) {
		hlua_pusherror(L, "socket: uninitialized pools.");
		goto out_fail_conf;
	}

	/* Pop a class stream metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_socket_ref);
	lua_setmetatable(L, -2);

	/* Create the applet context */
	appctx = appctx_new(&update_applet);
	if (!appctx) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_conf;
	}

	appctx->ctx.hlua.socket = socket;
	appctx->ctx.hlua.connected = 0;
	LIST_INIT(&appctx->ctx.hlua.wake_on_write);
	LIST_INIT(&appctx->ctx.hlua.wake_on_read);

	/* Now create a session, task and stream for this applet */
	sess = session_new(&socket_proxy, NULL, &appctx->obj_type);
	if (!sess) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_sess;
	}

	task = task_new();
	if (!task) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_task;
	}
	task->nice = 0;

	strm = stream_new(sess, task, &appctx->obj_type);
	if (!strm) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_stream;
	}

	/* Configure an empty Lua for the stream. */
	socket->s = strm;
	strm->hlua.T = NULL;
	strm->hlua.Tref = LUA_REFNIL;
	strm->hlua.Mref = LUA_REFNIL;
	strm->hlua.nargs = 0;
	strm->hlua.flags = 0;
	LIST_INIT(&strm->hlua.com);

	/* Configure "right" stream interface. this "si" is used to connect
	 * and retrieve data from the server. The connection is initialized
	 * with the "struct server".
	 */
	si_set_state(&strm->si[1], SI_ST_ASS);

	/* Force destination server. */
	strm->flags |= SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET | SF_BE_ASSIGNED;
	strm->target = &socket_tcp.obj_type;

	/* Update statistics counters. */
	socket_proxy.feconn++; /* beconn will be increased later */
	jobs++;
	totalconn++;

	/* Return yield waiting for connection. */
	return 1;

 out_fail_stream:
	task_free(task);
 out_fail_task:
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
	return (struct channel *)MAY_LJMP(hlua_checkudata(L, ud, class_channel_ref));
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
 * of the builded string.
 */
static inline int _hlua_channel_dup(struct channel *chn, lua_State *L)
{
	char *blk1;
	char *blk2;
	int len1;
	int len2;
	int ret;
	luaL_Buffer b;

	ret = bi_getblk_nc(chn, &blk1, &len1, &blk2, &len2);
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

	if (_hlua_channel_dup(chn, L) == 0)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_dup_yield, TICK_ETERNITY, 0));
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

	ret = _hlua_channel_dup(chn, L);
	if (unlikely(ret == 0))
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_get_yield, TICK_ETERNITY, 0));

	if (unlikely(ret == -1))
		return 1;

	chn->buf->i -= ret;
	return 1;
}

/* Check arguments for the fucntion "hlua_channel_get_yield". */
__LJMP static int hlua_channel_get(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "get"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_get_yield(L, 0, 0));
}

/* This functions consumes and returns one line. If the channel is closed,
 * and the last data does not contains a final '\n', the data are returned
 * without the final '\n'. When no more data are avalaible, it returns nil
 * value.
 */
__LJMP static int hlua_channel_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	char *blk1;
	char *blk2;
	int len1;
	int len2;
	int len;
	struct channel *chn;
	int ret;
	luaL_Buffer b;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	ret = bi_getline_nc(chn, &blk1, &len1, &blk2, &len2);
	if (ret == 0)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_getline_yield, TICK_ETERNITY, 0));

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
	buffer_replace2(chn->buf, chn->buf->p, chn->buf->p + len,  NULL, 0);
	return 1;
}

/* Check arguments for the fucntion "hlua_channel_getline_yield". */
__LJMP static int hlua_channel_getline(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "getline"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_getline_yield(L, 0, 0));
}

/* This function takes a string as input, and append it at the
 * input side of channel. If the data is too big, but a space
 * is probably available after sending some data, the function
 * yield. If the data is bigger than the buffer, or if the
 * channel is closed, it returns -1. otherwise, it returns the
 * amount of data writed.
 */
__LJMP static int hlua_channel_append_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int ret;
	int max;

	max = channel_recv_limit(chn) - buffer_len(chn->buf);
	if (max > len - l)
		max = len - l;

	ret = bi_putblk(chn, str + l, max);
	if (ret == -2 || ret == -3) {
		lua_pushinteger(L, -1);
		return 1;
	}
	if (ret == -1) {
		chn->flags |= CF_WAKE_WRITE;
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	}
	l += ret;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	max = channel_recv_limit(chn) - buffer_len(chn->buf);
	if (max == 0 && chn->buf->o == 0) {
		/* There are no space avalaible, and the output buffer is empty.
		 * in this case, we cannot add more data, so we cannot yield,
		 * we return the amount of copyied data.
		 */
		return 1;
	}
	if (l < len)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	return 1;
}

/* just a wrapper of "hlua_channel_append_yield". It returns the length
 * of the writed string, or -1 if the channel is closed or if the
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

/* just a wrapper of "hlua_channel_append_yield". This wrapper starts
 * his process by cleaning the buffer. The result is a replacement
 * of the current data. It returns the length of the writed string,
 * or -1 if the channel is closed or if the buffer size is too
 * little for the data.
 */
__LJMP static int hlua_channel_set(lua_State *L)
{
	struct channel *chn;

	MAY_LJMP(check_args(L, 2, "set"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, 0);

	chn->buf->i = 0;

	return MAY_LJMP(hlua_channel_append_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediatly
 * sent. The fcuntion returns the ammount of data writed. If the buffer
 * cannot contains the data, the function yield. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_channel_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int max;
	struct hlua *hlua = hlua_gethlua(L);

	if (unlikely(channel_output_closed(chn))) {
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Check if the buffer is avalaible because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (chn->buf->size == 0) {
		if (!stream_alloc_recv_buffer(chn)) {
			chn_prod(chn)->flags |= SI_FL_WAIT_ROOM;
			WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
		}
	}

	/* the writed data will be immediatly sent, so we can check
	 * the avalaible space without taking in account the reserve.
	 * The reserve is guaranted for the processing of incoming
	 * data, because the buffer will be flushed.
	 */
	max = chn->buf->size - buffer_len(chn->buf);

	/* If there are no space avalaible, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copyied data.
	 */
	if (max == 0 && chn->buf->o == 0)
		return 1;

	/* Adjust the real required length. */
	if (max > len - l)
		max = len - l;

	/* The buffer avalaible size may be not contiguous. This test
	 * detects a non contiguous buffer and realign it.
	 */
	if (bi_space_for_replace(chn->buf) < max)
		buffer_slow_realign(chn->buf);

	/* Copy input data in the buffer. */
	max = buffer_replace2(chn->buf, chn->buf->p, chn->buf->p, str + l, max);

	/* buffer replace considers that the input part is filled.
	 * so, I must forward these new data in the output part.
	 */
	b_adv(chn->buf, max);

	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If there are no space avalaible, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copyied data.
	 */
	max = chn->buf->size - buffer_len(chn->buf);
	if (max == 0 && chn->buf->o == 0)
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
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just a wraper of "_hlua_channel_send". This wrapper permits
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
 * imput. It returns the number of bytes forwarded.
 */
__LJMP static int hlua_channel_forward_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct channel *chn;
	int len;
	int l;
	int max;
	struct hlua *hlua = hlua_gethlua(L);

	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	len = MAY_LJMP(luaL_checkinteger(L, 2));
	l = MAY_LJMP(luaL_checkinteger(L, -1));

	max = len - l;
	if (max > chn->buf->i)
		max = chn->buf->i;
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
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_forward_yield, TICK_ETERNITY, 0));
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
	lua_pushinteger(L, chn->buf->i);
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
	lua_pushinteger(L, chn->buf->o);
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
	return (struct hlua_smp *)MAY_LJMP(hlua_checkudata(L, ud, class_fetches_ref));
}

/* This function creates and push in the stack a fetch object according
 * with a current TXN.
 */
static int hlua_fetches_new(lua_State *L, struct hlua_txn *txn, int stringsafe)
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
	hsmp->stringsafe = stringsafe;

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
	struct arg args[ARGM_NBARGS + 1];
	int i;
	struct sample smp;

	/* Get closure arguments. */
	f = (struct sample_fetch *)lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditionnal arguments. */
	hsmp = MAY_LJMP(hlua_checkfetches(L, 1));

	/* Get extra arguments. */
	for (i = 0; i < lua_gettop(L) - 1; i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 2, &args[i]);
	}
	args[i].type = ARGT_STOP;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 2, args, f->arg_mask, hsmp->p));

	/* Run the special args checker. */
	if (f->val_args && !f->val_args(args, NULL)) {
		lua_pushfstring(L, "error in arguments");
		WILL_LJMP(lua_error(L));
	}

	/* Initialise the sample. */
	memset(&smp, 0, sizeof(smp));

	/* Run the sample fetch process. */
	smp.px = hsmp->p;
	smp.sess = hsmp->s->sess;
	smp.strm = hsmp->s;
	smp.opt = 0;
	if (!f->process(args, &smp, f->kw, f->private)) {
		if (hsmp->stringsafe)
			lua_pushstring(L, "");
		else
			lua_pushnil(L);
		return 1;
	}

	/* Convert the returned sample in lua value. */
	if (hsmp->stringsafe)
		hlua_smp2lua_str(L, &smp);
	else
		hlua_smp2lua(L, &smp);
	return 1;
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
	return (struct hlua_smp *)MAY_LJMP(hlua_checkudata(L, ud, class_converters_ref));
}

/* This function creates and push in the stack a Converters object
 * according with a current TXN.
 */
static int hlua_converters_new(lua_State *L, struct hlua_txn *txn, int stringsafe)
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
	hsmp->stringsafe = stringsafe;

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
	struct arg args[ARGM_NBARGS + 1];
	int i;
	struct sample smp;

	/* Get closure arguments. */
	conv = (struct sample_conv *)lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditionnal arguments. */
	hsmp = MAY_LJMP(hlua_checkconverters(L, 1));

	/* Get extra arguments. */
	for (i = 0; i < lua_gettop(L) - 2; i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 3, &args[i]);
	}
	args[i].type = ARGT_STOP;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 3, args, conv->arg_mask, hsmp->p));

	/* Run the special args checker. */
	if (conv->val_args && !conv->val_args(args, conv, "", 0, NULL)) {
		hlua_pusherror(L, "error in arguments");
		WILL_LJMP(lua_error(L));
	}

	/* Initialise the sample. */
	if (!hlua_lua2smp(L, 2, &smp)) {
		hlua_pusherror(L, "error in the input argument");
		WILL_LJMP(lua_error(L));
	}

	/* Apply expected cast. */
	if (!sample_casts[smp.type][conv->in_type]) {
		hlua_pusherror(L, "invalid input argument: cannot cast '%s' to '%s'",
		               smp_to_type[smp.type], smp_to_type[conv->in_type]);
		WILL_LJMP(lua_error(L));
	}
	if (sample_casts[smp.type][conv->in_type] != c_none &&
	    !sample_casts[smp.type][conv->in_type](&smp)) {
		hlua_pusherror(L, "error during the input argument casting");
		WILL_LJMP(lua_error(L));
	}

	/* Run the sample conversion process. */
	smp.px = hsmp->p;
	smp.sess = hsmp->s->sess;
	smp.strm = hsmp->s;
	smp.opt = 0;
	if (!conv->process(args, &smp, conv->private)) {
		if (hsmp->stringsafe)
			lua_pushstring(L, "");
		else
                       lua_pushnil(L);
		return 1;
	}

	/* Convert the returned sample in lua value. */
	if (hsmp->stringsafe)
		hlua_smp2lua_str(L, &smp);
	else
		hlua_smp2lua(L, &smp);
        return 1;
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
	return (struct hlua_txn *)MAY_LJMP(hlua_checkudata(L, ud, class_http_ref));
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

	/* Pop a class stream metatable and affect it to the table. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_http_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function creates ans returns an array of HTTP headers.
 * This function does not fails. It is used as wrapper with the
 * 2 following functions.
 */
__LJMP static int hlua_http_get_headers(lua_State *L, struct hlua_txn *htxn, struct http_msg *msg)
{
	const char *cur_ptr, *cur_next, *p;
	int old_idx, cur_idx;
	struct hdr_idx_elem *cur_hdr;
	const char *hn, *hv;
	int hnl, hvl;
	int type;
	const char *in;
	char *out;
	int len;

	/* Create the table. */
	lua_newtable(L);

	if (!htxn->s->txn)
		return 1;

	/* Build array of headers. */
	old_idx = 0;
	cur_next = msg->chn->buf->p + hdr_idx_first_pos(&htxn->s->txn->hdr_idx);

	while (1) {
		cur_idx = htxn->s->txn->hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;
		old_idx = cur_idx;

		cur_hdr  = &htxn->s->txn->hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_next = cur_ptr + cur_hdr->len + cur_hdr->cr + 1;

		/* Now we have one full header at cur_ptr of len cur_hdr->len,
		 * and the next header starts at cur_next. We'll check
		 * this header in the list as well as against the default
		 * rule.
		 */

		/* look for ': *'. */
		hn = cur_ptr;
		for (p = cur_ptr; p < cur_ptr + cur_hdr->len && *p != ':'; p++);
		if (p >= cur_ptr+cur_hdr->len)
			continue;
		hnl = p - hn;
		p++;
		while (p < cur_ptr+cur_hdr->len && ( *p == ' ' || *p == '\t' ))
			p++;
		if (p >= cur_ptr+cur_hdr->len)
			continue;
		hv = p;
		hvl = cur_ptr+cur_hdr->len-p;

		/* Lowercase the key. Don't check the size of trash, it have
		 * the size of one buffer and the input data contains in one
		 * buffer.
		 */
		out = trash.str;
		for (in=hn; in<hn+hnl; in++, out++)
			*out = tolower(*in);
		*out = '\0';

		/* Check for existing entry:
		 * assume that the table is on the top of the stack, and
		 * push the key in the stack, the function lua_gettable()
		 * perform the lookup.
		 */
		lua_pushlstring(L, trash.str, hnl);
		lua_gettable(L, -2);
		type = lua_type(L, -1);

		switch (type) {
		case LUA_TNIL:
			/* Table not found, create it. */
			lua_pop(L, 1); /* remove the nil value. */
			lua_pushlstring(L, trash.str, hnl);  /* push the header name as key. */
			lua_newtable(L); /* create and push empty table. */
			lua_pushlstring(L, hv, hvl); /* push header value. */
			lua_rawseti(L, -2, 0); /* index header value (pop it). */
			lua_rawset(L, -3); /* index new table with header name (pop the values). */
			break;

		case LUA_TTABLE:
			/* Entry found: push the value in the table. */
			len = lua_rawlen(L, -1);
			lua_pushlstring(L, hv, hvl); /* push header value. */
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

	return hlua_http_get_headers(L, htxn, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_get_headers(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 1, "res_get_headers"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return hlua_http_get_headers(L, htxn, &htxn->s->txn->rsp);
}

/* This function replace full header, or just a value in
 * the request or in the response. It is a wrapper fir the
 * 4 following functions.
 */
__LJMP static inline int hlua_http_rep_hdr(lua_State *L, struct hlua_txn *htxn,
                                           struct http_msg *msg, int action)
{
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));
	const char *reg = MAY_LJMP(luaL_checkstring(L, 3));
	const char *value = MAY_LJMP(luaL_checkstring(L, 4));
	struct my_regex re;

	if (!regex_comp(reg, &re, 1, 1, NULL))
		WILL_LJMP(luaL_argerror(L, 3, "invalid regex"));

	http_transform_header_str(htxn->s, msg, name, name_len, value, &re, action);
	regex_free(&re);
	return 0;
}

__LJMP static int hlua_http_req_rep_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "req_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return MAY_LJMP(hlua_http_rep_hdr(L, htxn, &htxn->s->txn->req, HTTP_REQ_ACT_REPLACE_HDR));
}

__LJMP static int hlua_http_res_rep_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "res_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return MAY_LJMP(hlua_http_rep_hdr(L, htxn, &htxn->s->txn->rsp, HTTP_RES_ACT_REPLACE_HDR));
}

__LJMP static int hlua_http_req_rep_val(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "req_rep_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return MAY_LJMP(hlua_http_rep_hdr(L, htxn, &htxn->s->txn->req, HTTP_REQ_ACT_REPLACE_VAL));
}

__LJMP static int hlua_http_res_rep_val(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 4, "res_rep_val"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return MAY_LJMP(hlua_http_rep_hdr(L, htxn, &htxn->s->txn->rsp, HTTP_RES_ACT_REPLACE_VAL));
}

/* This function deletes all the occurences of an header.
 * It is a wrapper for the 2 following functions.
 */
__LJMP static inline int hlua_http_del_hdr(lua_State *L, struct hlua_txn *htxn, struct http_msg *msg)
{
	size_t len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &len));
	struct hdr_ctx ctx;
	struct http_txn *txn = htxn->s->txn;

	ctx.idx = 0;
	while (http_find_header2(name, len, msg->chn->buf->p, &txn->hdr_idx, &ctx))
		http_remove_header2(msg, &txn->hdr_idx, &ctx);
	return 0;
}

__LJMP static int hlua_http_req_del_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "req_del_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return hlua_http_del_hdr(L, htxn, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_del_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 2, "req_del_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return hlua_http_del_hdr(L, htxn, &htxn->s->txn->rsp);
}

/* This function adds an header. It is a wrapper used by
 * the 2 following functions.
 */
__LJMP static inline int hlua_http_add_hdr(lua_State *L, struct hlua_txn *htxn, struct http_msg *msg)
{
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));
	size_t value_len;
	const char *value = MAY_LJMP(luaL_checklstring(L, 3, &value_len));
	char *p;

	/* Check length. */
	trash.len = value_len + name_len + 2;
	if (trash.len > trash.size)
		return 0;

	/* Creates the header string. */
	p = trash.str;
	memcpy(p, name, name_len);
	p += name_len;
	*p = ':';
	p++;
	*p = ' ';
	p++;
	memcpy(p, value, value_len);

	lua_pushboolean(L, http_header_add_tail2(msg, &htxn->s->txn->hdr_idx,
	                                         trash.str, trash.len) != 0);

	return 0;
}

__LJMP static int hlua_http_req_add_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "req_add_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return hlua_http_add_hdr(L, htxn, &htxn->s->txn->req);
}

__LJMP static int hlua_http_res_add_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "res_add_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	return hlua_http_add_hdr(L, htxn, &htxn->s->txn->rsp);
}

static int hlua_http_req_set_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "req_set_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	hlua_http_del_hdr(L, htxn, &htxn->s->txn->req);
	return hlua_http_add_hdr(L, htxn, &htxn->s->txn->req);
}

static int hlua_http_res_set_hdr(lua_State *L)
{
	struct hlua_txn *htxn;

	MAY_LJMP(check_args(L, 3, "res_set_hdr"));
	htxn = MAY_LJMP(hlua_checkhttp(L, 1));

	hlua_http_del_hdr(L, htxn, &htxn->s->txn->rsp);
	return hlua_http_add_hdr(L, htxn, &htxn->s->txn->rsp);
}

/* This function set the method. */
static int hlua_http_req_set_meth(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	lua_pushboolean(L, http_replace_req_line(0, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the method. */
static int hlua_http_req_set_path(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));
	lua_pushboolean(L, http_replace_req_line(1, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the query-string. */
static int hlua_http_req_set_query(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	/* Check length. */
	if (name_len > trash.size - 1) {
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Add the mark question as prefix. */
	chunk_reset(&trash);
	trash.str[trash.len++] = '?';
	memcpy(trash.str + trash.len, name, name_len);
	trash.len += name_len;

	lua_pushboolean(L, http_replace_req_line(2, trash.str, trash.len, htxn->p, htxn->s) != -1);
	return 1;
}

/* This function set the uri. */
static int hlua_http_req_set_uri(lua_State *L)
{
	struct hlua_txn *htxn = MAY_LJMP(hlua_checkhttp(L, 1));
	size_t name_len;
	const char *name = MAY_LJMP(luaL_checklstring(L, 2, &name_len));

	lua_pushboolean(L, http_replace_req_line(3, name, name_len, htxn->p, htxn->s) != -1);
	return 1;
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
	return (struct hlua_txn *)MAY_LJMP(hlua_checkudata(L, ud, class_txn_ref));
}

__LJMP static int hlua_set_var(lua_State *L)
{
	struct hlua_txn *htxn;
	const char *name;
	size_t len;
	struct sample smp;

	MAY_LJMP(check_args(L, 3, "set_var"));

	/* It is useles to retrieve the stream, but this function
	 * runs only in a stream context.
	 */
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	name = MAY_LJMP(luaL_checklstring(L, 2, &len));

	/* Converts the third argument in a sample. */
	hlua_lua2smp(L, 3, &smp);

	/* Store the sample in a variable. */
	vars_set_by_name(name, len, htxn->s, &smp);
	return 0;
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

	if (!vars_get_by_name(name, len, htxn->s, &smp)) {
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
	hlua = hlua_gethlua(L);

	/* Remove previous value. */
	if (hlua->Mref != -1)
		luaL_unref(L, hlua->Mref, LUA_REGISTRYINDEX);

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
	hlua = hlua_gethlua(L);

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* Create stack entry containing a class TXN. This function
 * return 0 if the stack does not contains free slots,
 * otherwise it returns 1.
 */
static int hlua_txn_new(lua_State *L, struct stream *s, struct proxy *p)
{
	struct hlua_txn *htxn;

	/* Check stack size. */
	if (!lua_checkstack(L, 3))
		return 0;

	/* NOTE: The allocation never fails. The failure
	 * throw an error, and the function never returns.
	 * if the throw is not avalaible, the process is aborted.
	 */
	/* Create the object: obj[0] = userdata. */
	lua_newtable(L);
	htxn = lua_newuserdata(L, sizeof(*htxn));
	lua_rawseti(L, -2, 0);

	htxn->s = s;
	htxn->p = p;

	/* Create the "f" field that contains a list of fetches. */
	lua_pushstring(L, "f");
	if (!hlua_fetches_new(L, htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sf" field that contains a list of stringsafe fetches. */
	lua_pushstring(L, "sf");
	if (!hlua_fetches_new(L, htxn, 1))
		return 0;
	lua_settable(L, -3);

	/* Create the "c" field that contains a list of converters. */
	lua_pushstring(L, "c");
	if (!hlua_converters_new(L, htxn, 0))
		return 0;
	lua_settable(L, -3);

	/* Create the "sc" field that contains a list of stringsafe converters. */
	lua_pushstring(L, "sc");
	if (!hlua_converters_new(L, htxn, 1))
		return 0;
	lua_settable(L, -3);

	/* Create the "req" field that contains the request channel object. */
	lua_pushstring(L, "req");
	if (!hlua_channel_new(L, &s->req))
		return 0;
	lua_settable(L, -3);

	/* Create the "res" field that contains the response channel object. */
	lua_pushstring(L, "res");
	if (!hlua_channel_new(L, &s->res))
		return 0;
	lua_settable(L, -3);

	/* Creates the HTTP object is the current proxy allows http. */
	lua_pushstring(L, "http");
	if (p->mode == PR_MODE_HTTP) {
		if (!hlua_http_new(L, htxn))
			return 0;
	}
	else
		lua_pushnil(L);
	lua_settable(L, -3);

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
	struct connection *cli_conn;
	int tos;

	MAY_LJMP(check_args(L, 2, "set_tos"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	tos = MAY_LJMP(luaL_checkinteger(L, 2));

	if ((cli_conn = objt_conn(htxn->s->sess->origin)) && conn_ctrl_ready(cli_conn))
		inet_set_tos(cli_conn->t.sock.fd, cli_conn->addr.from, tos);

	return 0;
}

__LJMP static int hlua_txn_set_mark(lua_State *L)
{
#ifdef SO_MARK
	struct hlua_txn *htxn;
	struct connection *cli_conn;
	int mark;

	MAY_LJMP(check_args(L, 2, "set_mark"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));
	mark = MAY_LJMP(luaL_checkinteger(L, 2));

	if ((cli_conn = objt_conn(htxn->s->sess->origin)) && conn_ctrl_ready(cli_conn))
		setsockopt(cli_conn->t.sock.fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#endif
	return 0;
}

/* This function is an Lua binding that send pending data
 * to the client, and close the stream interface.
 */
__LJMP static int hlua_txn_close(lua_State *L)
{
	struct hlua_txn *htxn;
	struct channel *ic, *oc;

	MAY_LJMP(check_args(L, 1, "close"));
	htxn = MAY_LJMP(hlua_checktxn(L, 1));

	ic = &htxn->s->req;
	oc = &htxn->s->res;

	channel_abort(ic);
	channel_auto_close(ic);
	channel_erase(ic);
	channel_auto_read(oc);
	channel_auto_close(oc);
	channel_shutr_now(oc);

	return 0;
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
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
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

	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
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

	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
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
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_yield_yield, TICK_ETERNITY, HLUA_CTRLYIELD));
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
	hlua = hlua_gethlua(L);
	nice = MAY_LJMP(luaL_checkinteger(L, 1));

	/* If he task is not set, I'm in a start mode. */
	if (!hlua || !hlua->task)
		return 0;

	if (nice < -1024)
		nice = -1024;
	else if (nice > 1024)
		nice = 1024;

	hlua->task->nice = nice;
	return 0;
}

/* This function is used as a calback of a task. It is called by the
 * HAProxy task subsystem when the task is awaked. The LUA runtime can
 * return an E_AGAIN signal, the emmiter of this signal must set a
 * signal to wake the task.
 */
static struct task *hlua_process_task(struct task *task)
{
	struct hlua *hlua = task->context;
	enum hlua_exec status;

	/* We need to remove the task from the wait queue before executing
	 * the Lua code because we don't know if it needs to wait for
	 * another timer or not in the case of E_AGAIN.
	 */
	task_delete(task);

	/* If it is the first call to the task, we must initialize the
	 * execution timeouts.
	 */
	if (!HLUA_IS_RUNNING(hlua))
		hlua->expire = tick_add(now_ms, hlua_timeout_task);

	/* Execute the Lua code. */
	status = hlua_ctx_resume(hlua, 1);

	switch (status) {
	/* finished or yield */
	case HLUA_E_OK:
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;

	case HLUA_E_AGAIN: /* co process or timeout wake me later. */
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(task, hlua->wake_time);
		break;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		send_log(NULL, LOG_ERR, "Lua task: %s.", lua_tostring(hlua->T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua task: %s.\n", lua_tostring(hlua->T, -1));
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;

	case HLUA_E_ERR:
	default:
		send_log(NULL, LOG_ERR, "Lua task: unknown error.");
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua task: unknown error.\n");
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;
	}
	return NULL;
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

	init = malloc(sizeof(*init));
	if (!init)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	init->function_ref = ref;
	LIST_ADDQ(&hlua_init_functions, &init->l);
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

	MAY_LJMP(check_args(L, 1, "register_task"));

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	hlua = malloc(sizeof(*hlua));
	if (!hlua)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	task = task_new();
	task->context = hlua;
	task->process = hlua_process_task;

	if (!hlua_ctx_init(hlua, task))
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

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
	struct hlua_function *fcn = (struct hlua_function *)private;
	struct stream *stream = smp->strm;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!stream->hlua.T && !hlua_ctx_init(&stream->hlua, stream->task)) {
		send_log(stream->be, LOG_ERR, "Lua converter '%s': can't initialize Lua context.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&stream->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(stream->hlua.T, 1)) {
			send_log(stream->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(stream->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* convert input sample and pust-it in the stack. */
		if (!lua_checkstack(stream->hlua.T, 1)) {
			send_log(stream->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}
		hlua_smp2lua(stream->hlua.T, smp);
		stream->hlua.nargs = 2;

		/* push keywords in the stack. */
		if (arg_p) {
			for (; arg_p->type != ARGT_STOP; arg_p++) {
				if (!lua_checkstack(stream->hlua.T, 1)) {
					send_log(stream->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
					if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
						Alert("Lua converter '%s': full stack.\n", fcn->name);
					return 0;
				}
				hlua_arg2lua(stream->hlua.T, arg_p);
				stream->hlua.nargs++;
			}
		}

		/* We must initialize the execution timeouts. */
		stream->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&stream->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&stream->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(stream->hlua.T, -1, smp);
		lua_pop(stream->hlua.T, 1);
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(stream->be, LOG_ERR, "Lua converter '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(stream->be, LOG_ERR, "Lua converter '%s': %s.", fcn->name, lua_tostring(stream->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': %s.\n", fcn->name, lua_tostring(stream->hlua.T, -1));
		lua_pop(stream->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(stream->be, LOG_ERR, "Lua converter '%s' returns an unknown error.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s' returns an unknown error.\n", fcn->name);

	default:
		return 0;
	}
}

/* Wrapper called by HAProxy to execute a sample-fetch. this wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume sample-fetches.
 */
static int hlua_sample_fetch_wrapper(const struct arg *arg_p, struct sample *smp,
                                     const char *kw, void *private)
{
	struct hlua_function *fcn = (struct hlua_function *)private;
	struct stream *stream = smp->strm;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!stream->hlua.T && !hlua_ctx_init(&stream->hlua, stream->task)) {
		send_log(stream->be, LOG_ERR, "Lua sample-fetch '%s': can't initialize Lua context.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&stream->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(stream->hlua.T, 2)) {
			send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(stream->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* push arguments in the stack. */
		if (!hlua_txn_new(stream->hlua.T, stream, smp->px)) {
			send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}
		stream->hlua.nargs = 1;

		/* push keywords in the stack. */
		for (; arg_p && arg_p->type != ARGT_STOP; arg_p++) {
			/* Check stack available size. */
			if (!lua_checkstack(stream->hlua.T, 1)) {
				send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			if (!lua_checkstack(stream->hlua.T, 1)) {
				send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			hlua_arg2lua(stream->hlua.T, arg_p);
			stream->hlua.nargs++;
		}

		/* We must initialize the execution timeouts. */
		stream->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&stream->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&stream->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(stream->hlua.T, -1, smp);
		lua_pop(stream->hlua.T, 1);

		/* Set the end of execution flag. */
		smp->flags &= ~SMP_F_MAY_CHANGE;
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s': %s.", fcn->name, lua_tostring(stream->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': %s.\n", fcn->name, lua_tostring(stream->hlua.T, -1));
		lua_pop(stream->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(smp->px, LOG_ERR, "Lua sample-fetch '%s' returns an unknown error.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': returns an unknown error.\n", fcn->name);

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

	MAY_LJMP(check_args(L, 2, "register_converters"));

	/* First argument : converter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Allocate and fill the sample fetch keyword struct. */
	sck = malloc(sizeof(*sck) + sizeof(struct sample_conv) * 2);
	if (!sck)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn = malloc(sizeof(*fcn));
	if (!fcn)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn->function_ref = ref;

	/* List head */
	sck->list.n = sck->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sck->kw[0].kw = malloc(len);
	if (!sck->kw[0].kw)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	snprintf((char *)sck->kw[0].kw, len, "lua.%s", name);
	sck->kw[0].process = hlua_sample_conv_wrapper;
	sck->kw[0].arg_mask = ARG5(0,STR,STR,STR,STR,STR);
	sck->kw[0].val_args = NULL;
	sck->kw[0].in_type = SMP_T_STR;
	sck->kw[0].out_type = SMP_T_STR;
	sck->kw[0].private = fcn;

	/* End of array. */
	memset(&sck->kw[1], 0, sizeof(struct sample_conv));

	/* Register this new converter */
	sample_register_convs(sck);

	return 0;
}

/* This fucntion is an LUA binding used for registering
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

	MAY_LJMP(check_args(L, 2, "register_fetches"));

	/* First argument : sample-fetch name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Allocate and fill the sample fetch keyword struct. */
	sfk = malloc(sizeof(*sfk) + sizeof(struct sample_fetch) * 2);
	if (!sfk)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn = malloc(sizeof(*fcn));
	if (!fcn)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn->function_ref = ref;

	/* List head */
	sfk->list.n = sfk->list.p = NULL;

	/* sample-fetch keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sfk->kw[0].kw = malloc(len);
	if (!sfk->kw[0].kw)
		return luaL_error(L, "lua out of memory error.");

	snprintf((char *)sfk->kw[0].kw, len, "lua.%s", name);
	sfk->kw[0].process = hlua_sample_fetch_wrapper;
	sfk->kw[0].arg_mask = ARG5(0,STR,STR,STR,STR,STR);
	sfk->kw[0].val_args = NULL;
	sfk->kw[0].out_type = SMP_T_STR;
	sfk->kw[0].use = SMP_USE_HTTP_ANY;
	sfk->kw[0].val = 0;
	sfk->kw[0].private = fcn;

	/* End of array. */
	memset(&sfk->kw[1], 0, sizeof(struct sample_fetch));

	/* Register this new fetch. */
	sample_register_fetches(sfk);

	return 0;
}

/* global {tcp|http}-request parser. Return 1 in succes case, else return 0. */
static int hlua_parse_rule(const char **args, int *cur_arg, struct proxy *px,
                           struct hlua_rule **rule_p, char **err)
{
	struct hlua_rule *rule;

	/* Memory for the rule. */
	rule = malloc(sizeof(*rule));
	if (!rule) {
		memprintf(err, "out of memory error");
		return 0;
	}
	*rule_p = rule;

	/* The requiered arg is a function name. */
	if (!args[*cur_arg]) {
		memprintf(err, "expect Lua function name");
		return 0;
	}

	/* Lookup for the symbol, and check if it is a function. */
	lua_getglobal(gL.T, args[*cur_arg]);
	if (lua_isnil(gL.T, -1)) {
		lua_pop(gL.T, 1);
		memprintf(err, "Lua function '%s' not found", args[*cur_arg]);
		return 0;
	}
	if (!lua_isfunction(gL.T, -1)) {
		lua_pop(gL.T, 1);
		memprintf(err, "'%s' is not a function",  args[*cur_arg]);
		return 0;
	}

	/* Reference the Lua function and store the reference. */
	rule->fcn.function_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX);
	rule->fcn.name = strdup(args[*cur_arg]);
	if (!rule->fcn.name) {
		memprintf(err, "out of memory error.");
		return 0;
	}
	(*cur_arg)++;

	/* TODO: later accept arguments. */
	rule->args = NULL;

	return 1;
}

/* This function is a wrapper to execute each LUA function declared
 * as an action wrapper during the initialisation period. This function
 * return 1 if the processing is finished (with oe without error) and
 * return 0 if the function must be called again because the LUA
 * returns a yield.
 */
static int hlua_request_act_wrapper(struct hlua_rule *rule, struct proxy *px,
                                    struct stream *s, unsigned int analyzer)
{
	char **arg;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!s->hlua.T && !hlua_ctx_init(&s->hlua, s->task)) {
		send_log(px, LOG_ERR, "Lua action '%s': can't initialize Lua context.", rule->fcn.name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua action '%s': can't initialize Lua context.\n", rule->fcn.name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&s->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(s->hlua.T, 1)) {
			send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua function '%s': full stack.\n", rule->fcn.name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(s->hlua.T, LUA_REGISTRYINDEX, rule->fcn.function_ref);

		/* Create and and push object stream in the stack. */
		if (!hlua_txn_new(s->hlua.T, s, px)) {
			send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua function '%s': full stack.\n", rule->fcn.name);
			return 0;
		}
		s->hlua.nargs = 1;

		/* push keywords in the stack. */
		for (arg = rule->args; arg && *arg; arg++) {
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua function '%s': full stack.\n", rule->fcn.name);
				return 0;
			}
			lua_pushstring(s->hlua.T, *arg);
			s->hlua.nargs++;
		}

		/* We must initialize the execution timeouts. */
		s->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&s->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&s->hlua, 1)) {
	/* finished. */
	case HLUA_E_OK:
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		/* Set timeout in the required channel. */
		if (s->hlua.wake_time != TICK_ETERNITY) {
			if (analyzer & (AN_REQ_INSPECT_FE|AN_REQ_HTTP_PROCESS_FE))
				s->req.analyse_exp = s->hlua.wake_time;
			else if (analyzer & (AN_RES_INSPECT|AN_RES_HTTP_PROCESS_BE))
				s->res.analyse_exp = s->hlua.wake_time;
		}
		/* Some actions can be wake up when a "write" event
		 * is detected on a response channel. This is useful
		 * only for actions targetted on the requests.
		 */
		if (HLUA_IS_WAKERESWR(&s->hlua)) {
			s->res.flags |= CF_WAKE_WRITE;
			if ((analyzer & (AN_REQ_INSPECT_FE|AN_REQ_HTTP_PROCESS_FE)))
				s->res.analysers |= analyzer;
		}
		if (HLUA_IS_WAKEREQWR(&s->hlua))
			s->req.flags |= CF_WAKE_WRITE;
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua function '%s': %s.", rule->fcn.name, lua_tostring(s->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua function '%s': %s.\n", rule->fcn.name, lua_tostring(s->hlua.T, -1));
		lua_pop(s->hlua.T, 1);
		return 1;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua function '%s' return an unknown error.", rule->fcn.name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua function '%s' return an unknown error.\n", rule->fcn.name);

	default:
		return 1;
	}
}

/* Lua execution wrapper for "tcp-request". This function uses
 * "hlua_request_act_wrapper" for executing the LUA code.
 */
int hlua_tcp_req_act_wrapper(struct tcp_rule *tcp_rule, struct proxy *px,
                             struct stream *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)tcp_rule->act_prm.data[0],
	                                px, s, AN_REQ_INSPECT_FE);
}

/* Lua execution wrapper for "tcp-response". This function uses
 * "hlua_request_act_wrapper" for executing the LUA code.
 */
int hlua_tcp_res_act_wrapper(struct tcp_rule *tcp_rule, struct proxy *px,
                             struct stream *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)tcp_rule->act_prm.data[0],
	                                px, s, AN_RES_INSPECT);
}

/* Lua execution wrapper for http-request.
 * This function uses "hlua_request_act_wrapper" for executing
 * the LUA code.
 */
int hlua_http_req_act_wrapper(struct http_req_rule *rule, struct proxy *px,
                              struct stream *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)rule->arg.data, px,
	                                s, AN_REQ_HTTP_PROCESS_FE);
}

/* Lua execution wrapper for http-response.
 * This function uses "hlua_request_act_wrapper" for executing
 * the LUA code.
 */
int hlua_http_res_act_wrapper(struct http_res_rule *rule, struct proxy *px,
                              struct stream *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)rule->arg.data, px,
	                                s, AN_RES_HTTP_PROCESS_BE);
}

/* tcp-request <*> configuration wrapper. */
static int tcp_req_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                       struct tcp_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->act_prm.data[0], err))
		return 0;
	rule->action = TCP_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_tcp_req_act_wrapper;
	return 1;
}

/* tcp-response <*> configuration wrapper. */
static int tcp_res_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                       struct tcp_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->act_prm.data[0], err))
		return 0;
	rule->action = TCP_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_tcp_res_act_wrapper;
	return 1;
}

/* http-request <*> configuration wrapper. */
static int http_req_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                        struct http_req_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->arg.data, err))
		return -1;
	rule->action = HTTP_REQ_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_http_req_act_wrapper;
	return 1;
}

/* http-response <*> configuration wrapper. */
static int http_res_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                        struct http_res_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->arg.data, err))
		return -1;
	rule->action = HTTP_RES_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_http_res_act_wrapper;
	return 1;
}

static int hlua_read_timeout(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err, unsigned int *timeout)
{
	const char *error;

	error = parse_time_err(args[1], timeout, TIME_UNIT_MS);
	if (error && *error != '\0') {
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
 * This funtion runs with the HAProxy keywords API. It returns -1 if an error is
 * occured, otherwise it returns 0.
 *
 * In some error case, LUA set an error message in top of the stack. This function
 * returns this error message in the HAProxy logs and pop it from the stack.
 */
static int hlua_load(char **args, int section_type, struct proxy *curpx,
                     struct proxy *defpx, const char *file, int line,
                     char **err)
{
	int error;

	/* Just load and compile the file. */
	error = luaL_loadfile(gL.T, args[1]);
	if (error) {
		memprintf(err, "error in lua file '%s': %s", args[1], lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	}

	/* If no syntax error where detected, execute the code. */
	error = lua_pcall(gL.T, 0, LUA_MULTRET, 0);
	switch (error) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		memprintf(err, "lua runtime error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	case LUA_ERRMEM:
		memprintf(err, "lua out of memory error\n");
		return -1;
	case LUA_ERRERR:
		memprintf(err, "lua message handler error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	case LUA_ERRGCMM:
		memprintf(err, "lua garbage collector error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	default:
		memprintf(err, "lua unknonwn error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	}

	return 0;
}

/* configuration keywords declaration */
static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "lua-load",                 hlua_load },
	{ CFG_GLOBAL, "tune.lua.session-timeout", hlua_session_timeout },
	{ CFG_GLOBAL, "tune.lua.task-timeout",    hlua_task_timeout },
	{ CFG_GLOBAL, "tune.lua.forced-yield",    hlua_forced_yield },
	{ CFG_GLOBAL, "tune.lua.maxmem",          hlua_parse_maxmem },
	{ 0, NULL, NULL },
}};

static struct http_req_action_kw_list http_req_kws = {"lua", { }, {
	{ "lua", http_req_action_register_lua },
	{ NULL, NULL }
}};

static struct http_res_action_kw_list http_res_kws = {"lua", { }, {
	{ "lua", http_res_action_register_lua },
	{ NULL, NULL }
}};

static struct tcp_action_kw_list tcp_req_cont_kws = {"lua", { }, {
	{ "lua", tcp_req_action_register_lua },
	{ NULL, NULL }
}};

static struct tcp_action_kw_list tcp_res_cont_kws = {"lua", { }, {
	{ "lua", tcp_res_action_register_lua },
	{ NULL, NULL }
}};

int hlua_post_init()
{
	struct hlua_init_function *init;
	const char *msg;
	enum hlua_exec ret;

	list_for_each_entry(init, &hlua_init_functions, l) {
		lua_rawgeti(gL.T, LUA_REGISTRYINDEX, init->function_ref);
		ret = hlua_ctx_resume(&gL, 0);
		switch (ret) {
		case HLUA_E_OK:
			lua_pop(gL.T, -1);
			return 1;
		case HLUA_E_AGAIN:
			Alert("lua init: yield not allowed.\n");
			return 0;
		case HLUA_E_ERRMSG:
			msg = lua_tostring(gL.T, -1);
			Alert("lua init: %s.\n", msg);
			return 0;
		case HLUA_E_ERR:
		default:
			Alert("lua init: unknown runtime error.\n");
			return 0;
		}
	}
	return 1;
}

/* The memory allocator used by the Lua stack. <ud> is a pointer to the
 * allocator's context. <ptr> is the pointer to alloc/free/realloc. <osize>
 * is the previously allocated size or the kind of object in case of a new
 * allocation. <nsize> is the requested new size.
 */
static void *hlua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct hlua_mem_allocator *zone = ud;

	if (nsize == 0) {
		/* it's a free */
		if (ptr)
			zone->allocated -= osize;
		free(ptr);
		return NULL;
	}

	if (!ptr) {
		/* it's a new allocation */
		if (zone->limit && zone->allocated + nsize > zone->limit)
			return NULL;

		ptr = malloc(nsize);
		if (ptr)
			zone->allocated += nsize;
		return ptr;
	}

	/* it's a realloc */
	if (zone->limit && zone->allocated + nsize - osize > zone->limit)
		return NULL;

	ptr = realloc(ptr, nsize);
	if (ptr)
		zone->allocated += nsize - osize;
	return ptr;
}

void hlua_init(void)
{
	int i;
	int idx;
	struct sample_fetch *sf;
	struct sample_conv *sc;
	char *p;
#ifdef USE_OPENSSL
	struct srv_kw *kw;
	int tmp_error;
	char *error;
	char *args[] = { /* SSL client configuration. */
		"ssl",
		"verify",
		"none",
		"force-sslv3",
		NULL
	};
#endif

	/* Initialise com signals pool */
	pool2_hlua_com = create_pool("hlua_com", sizeof(struct hlua_com), MEM_F_SHARED);

	/* Register configuration keywords. */
	cfg_register_keywords(&cfg_kws);

	/* Register custom HTTP rules. */
	http_req_keywords_register(&http_req_kws);
	http_res_keywords_register(&http_res_kws);
	tcp_req_cont_keywords_register(&tcp_req_cont_kws);
	tcp_res_cont_keywords_register(&tcp_res_cont_kws);

	/* Init main lua stack. */
	gL.Mref = LUA_REFNIL;
	gL.flags = 0;
	LIST_INIT(&gL.com);
	gL.T = luaL_newstate();
	hlua_sethlua(&gL);
	gL.Tref = LUA_REFNIL;
	gL.task = NULL;

	/* change the memory allocators to track memory usage */
	lua_setallocf(gL.T, hlua_alloc, &hlua_global_allocator);

	/* Initialise lua. */
	luaL_openlibs(gL.T);

	/*
	 *
	 * Create "core" object.
	 *
	 */

	/* This table entry is the object "core" base. */
	lua_newtable(gL.T);

	/* Push the loglevel constants. */
	for (i = 0; i < NB_LOG_LEVELS; i++)
		hlua_class_const_int(gL.T, log_levels[i], i);

	/* Register special functions. */
	hlua_class_function(gL.T, "register_init", hlua_register_init);
	hlua_class_function(gL.T, "register_task", hlua_register_task);
	hlua_class_function(gL.T, "register_fetches", hlua_register_fetches);
	hlua_class_function(gL.T, "register_converters", hlua_register_converters);
	hlua_class_function(gL.T, "yield", hlua_yield);
	hlua_class_function(gL.T, "set_nice", hlua_set_nice);
	hlua_class_function(gL.T, "sleep", hlua_sleep);
	hlua_class_function(gL.T, "msleep", hlua_msleep);
	hlua_class_function(gL.T, "add_acl", hlua_add_acl);
	hlua_class_function(gL.T, "del_acl", hlua_del_acl);
	hlua_class_function(gL.T, "set_map", hlua_set_map);
	hlua_class_function(gL.T, "del_map", hlua_del_map);
	hlua_class_function(gL.T, "tcp", hlua_socket_new);
	hlua_class_function(gL.T, "log", hlua_log);
	hlua_class_function(gL.T, "Debug", hlua_log_debug);
	hlua_class_function(gL.T, "Info", hlua_log_info);
	hlua_class_function(gL.T, "Warning", hlua_log_warning);
	hlua_class_function(gL.T, "Alert", hlua_log_alert);

	lua_setglobal(gL.T, "core");

	/*
	 *
	 * Register class Map
	 *
	 */

	/* This table entry is the object "Map" base. */
	lua_newtable(gL.T);

	/* register pattern types. */
	for (i=0; i<PAT_MATCH_NUM; i++)
		hlua_class_const_int(gL.T, pat_match_names[i], i);

	/* register constructor. */
	hlua_class_function(gL.T, "new", hlua_map_new);

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Register . */
	hlua_class_function(gL.T, "lookup", hlua_map_lookup);
	hlua_class_function(gL.T, "slookup", hlua_map_slookup);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_MAP); /* register class session. */
	class_map_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/* Assign the metatable to the mai Map object. */
	lua_setmetatable(gL.T, -2);

	/* Set a name to the table. */
	lua_setglobal(gL.T, "Map");

	/*
	 *
	 * Register class Channel
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Register . */
	hlua_class_function(gL.T, "get",         hlua_channel_get);
	hlua_class_function(gL.T, "dup",         hlua_channel_dup);
	hlua_class_function(gL.T, "getline",     hlua_channel_getline);
	hlua_class_function(gL.T, "set",         hlua_channel_set);
	hlua_class_function(gL.T, "append",      hlua_channel_append);
	hlua_class_function(gL.T, "send",        hlua_channel_send);
	hlua_class_function(gL.T, "forward",     hlua_channel_forward);
	hlua_class_function(gL.T, "get_in_len",  hlua_channel_get_in_len);
	hlua_class_function(gL.T, "get_out_len", hlua_channel_get_out_len);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_CHANNEL); /* register class session. */
	class_channel_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class Fetches
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Browse existing fetches and create the associated
	 * object method.
	 */
	sf = NULL;
	while ((sf = sample_fetch_getnext(sf, &idx)) != NULL) {

		/* Dont register the keywork if the arguments check function are
		 * not safe during the runtime.
		 */
		if ((sf->val_args != NULL) &&
		    (sf->val_args != val_payload_lv) &&
			 (sf->val_args != val_hdr))
			continue;

		/* gL.Tua doesn't support '.' and '-' in the function names, replace it
		 * by an underscore.
		 */
		strncpy(trash.str, sf->kw, trash.size);
		trash.str[trash.size - 1] = '\0';
		for (p = trash.str; *p; p++)
			if (*p == '.' || *p == '-' || *p == '+')
				*p = '_';

		/* Register the function. */
		lua_pushstring(gL.T, trash.str);
		lua_pushlightuserdata(gL.T, sf);
		lua_pushcclosure(gL.T, hlua_run_sample_fetch, 1);
		lua_settable(gL.T, -3);
	}

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_FETCHES); /* register class session. */
	class_fetches_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class Converters
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fill the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Browse existing converters and create the associated
	 * object method.
	 */
	sc = NULL;
	while ((sc = sample_conv_getnext(sc, &idx)) != NULL) {
		/* Dont register the keywork if the arguments check function are
		 * not safe during the runtime.
		 */
		if (sc->val_args != NULL)
			continue;

		/* gL.Tua doesn't support '.' and '-' in the function names, replace it
		 * by an underscore.
		 */
		strncpy(trash.str, sc->kw, trash.size);
		trash.str[trash.size - 1] = '\0';
		for (p = trash.str; *p; p++)
			if (*p == '.' || *p == '-' || *p == '+')
				*p = '_';

		/* Register the function. */
		lua_pushstring(gL.T, trash.str);
		lua_pushlightuserdata(gL.T, sc);
		lua_pushcclosure(gL.T, hlua_run_sample_conv, 1);
		lua_settable(gL.T, -3);
	}

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_CONVERTERS); /* register class session. */
	class_converters_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class HTTP
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Register Lua functions. */
	hlua_class_function(gL.T, "req_get_headers",hlua_http_req_get_headers);
	hlua_class_function(gL.T, "req_del_header", hlua_http_req_del_hdr);
	hlua_class_function(gL.T, "req_rep_header", hlua_http_req_rep_hdr);
	hlua_class_function(gL.T, "req_rep_value",  hlua_http_req_rep_val);
	hlua_class_function(gL.T, "req_add_header", hlua_http_req_add_hdr);
	hlua_class_function(gL.T, "req_set_header", hlua_http_req_set_hdr);
	hlua_class_function(gL.T, "req_set_method", hlua_http_req_set_meth);
	hlua_class_function(gL.T, "req_set_path",   hlua_http_req_set_path);
	hlua_class_function(gL.T, "req_set_query",  hlua_http_req_set_query);
	hlua_class_function(gL.T, "req_set_uri",    hlua_http_req_set_uri);

	hlua_class_function(gL.T, "res_get_headers",hlua_http_res_get_headers);
	hlua_class_function(gL.T, "res_del_header", hlua_http_res_del_hdr);
	hlua_class_function(gL.T, "res_rep_header", hlua_http_res_rep_hdr);
	hlua_class_function(gL.T, "res_rep_value",  hlua_http_res_rep_val);
	hlua_class_function(gL.T, "res_add_header", hlua_http_res_add_hdr);
	hlua_class_function(gL.T, "res_set_header", hlua_http_res_set_hdr);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_HTTP); /* register class session. */
	class_http_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class TXN
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Register Lua functions. */
	hlua_class_function(gL.T, "set_priv",    hlua_set_priv);
	hlua_class_function(gL.T, "get_priv",    hlua_get_priv);
	hlua_class_function(gL.T, "set_var",     hlua_set_var);
	hlua_class_function(gL.T, "get_var",     hlua_get_var);
	hlua_class_function(gL.T, "close",       hlua_txn_close);
	hlua_class_function(gL.T, "set_loglevel",hlua_txn_set_loglevel);
	hlua_class_function(gL.T, "set_tos",     hlua_txn_set_tos);
	hlua_class_function(gL.T, "set_mark",    hlua_txn_set_mark);
	hlua_class_function(gL.T, "deflog",      hlua_txn_deflog);
	hlua_class_function(gL.T, "log",         hlua_txn_log);
	hlua_class_function(gL.T, "Debug",       hlua_txn_log_debug);
	hlua_class_function(gL.T, "Info",        hlua_txn_log_info);
	hlua_class_function(gL.T, "Warning",     hlua_txn_log_warning);
	hlua_class_function(gL.T, "Alert",       hlua_txn_log_alert);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_TXN); /* register class session. */
	class_txn_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class Socket
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

#ifdef USE_OPENSSL
	hlua_class_function(gL.T, "connect_ssl", hlua_socket_connect_ssl);
#endif
	hlua_class_function(gL.T, "connect",     hlua_socket_connect);
	hlua_class_function(gL.T, "send",        hlua_socket_send);
	hlua_class_function(gL.T, "receive",     hlua_socket_receive);
	hlua_class_function(gL.T, "close",       hlua_socket_close);
	hlua_class_function(gL.T, "getpeername", hlua_socket_getpeername);
	hlua_class_function(gL.T, "getsockname", hlua_socket_getsockname);
	hlua_class_function(gL.T, "setoption",   hlua_socket_setoption);
	hlua_class_function(gL.T, "settimeout",  hlua_socket_settimeout);

	lua_settable(gL.T, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register the garbage collector entry. */
	lua_pushstring(gL.T, "__gc");
	lua_pushcclosure(gL.T, hlua_socket_gc, 0);
	lua_settable(gL.T, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_SOCKET); /* register class socket. */
	class_socket_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class socket. */

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
	LIST_INIT(&socket_tcp.pendconns);
	socket_tcp.state = SRV_ST_RUNNING; /* early server setup */
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

	socket_tcp.xprt = &raw_sock;

#ifdef USE_OPENSSL
	/* Init TCP server: unchanged parameters */
	memset(&socket_ssl, 0, sizeof(socket_ssl));
	socket_ssl.next = NULL;
	socket_ssl.proxy = &socket_proxy;
	socket_ssl.obj_type = OBJ_TYPE_SERVER;
	LIST_INIT(&socket_ssl.actconns);
	LIST_INIT(&socket_ssl.pendconns);
	socket_ssl.state = SRV_ST_RUNNING; /* early server setup */
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
	socket_ssl.xprt = &ssl_sock;

	for (idx = 0; args[idx] != NULL; idx++) {
		if ((kw = srv_find_kw(args[idx])) != NULL) { /* Maybe it's registered server keyword */
			/*
			 *
			 * If the keyword is not known, we can search in the registered
			 * server keywords. This is usefull to configure special SSL
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

	/* Initialize SSL server. */
	ssl_sock_prepare_srv_ctx(&socket_ssl, &socket_proxy);
#endif
}
