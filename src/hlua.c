#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <ebpttree.h>

#include <common/cfgparse.h>

#include <types/hlua.h>
#include <types/proto_tcp.h>
#include <types/proxy.h>

#include <proto/arg.h>
#include <proto/hdr_idx.h>
#include <proto/payload.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/task.h>

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

/* List head of the function called at the initialisation time. */
struct list hlua_init_functions = LIST_HEAD_INIT(hlua_init_functions);

/* Store the fast lua context for coroutines. This tree uses the
 * Lua stack pointer value as indexed entry, and store the associated
 * hlua context.
 */
struct eb_root hlua_ctx = EB_ROOT_UNIQUE;

/* The following variables contains the reference of the different
 * Lua classes. These references are useful for identify metadata
 * associated with an object.
 */
static int class_core_ref;
static int class_txn_ref;

/* These functions converts types between HAProxy internal args or
 * sample and LUA types. Another function permits to check if the
 * LUA stack contains arguments according with an required ARG_T
 * format.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg);
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg);
__LJMP static int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp, unsigned int mask);
static int hlua_smp2lua(lua_State *L, const struct sample *smp);
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
                                        unsigned int value)
{
	if (!lua_checkstack(L, 2))
	WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushunsigned(L, value);
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
static int hlua_udataistype(lua_State *L, int ud, int class_ref)
{
	void *p = lua_touserdata(L, ud);
	if (!p)
		return 0;

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
	if (!hlua_udataistype(L, ud, class_ref))
		WILL_LJMP(luaL_argerror(L, 1, NULL));
	return lua_touserdata(L, ud);
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
		lua_pushunsigned(L, arg->data.sint);
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
static int hlua_smp2lua(lua_State *L, const struct sample *smp)
{
	switch (smp->type) {
	case SMP_T_SINT:
		lua_pushinteger(L, smp->data.sint);
		break;

	case SMP_T_BOOL:
	case SMP_T_UINT:
		lua_pushunsigned(L, smp->data.uint);
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
	default:
		lua_pushnil(L);
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
 */
__LJMP int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp, unsigned int mask)
{
	int min_arg;
	int idx;

	idx = 0;
	min_arg = ARGM(mask);
	mask >>= ARGM_BITS;

	while (1) {

		/* Check oversize. */
		if (idx >= ARGM_NBARGS && argp[idx].type != ARGT_STOP) {
			WILL_LJMP(luaL_argerror(L, first + idx, "Malformad argument mask"));
		}

		/* Check for mandatory arguments. */
		if (argp[idx].type == ARGT_STOP) {
			if (idx + 1 < min_arg)
				WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));
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

		/* Compatibility mask. */
		switch (argp[idx].type) {
		case ARGT_SINT:
			switch (mask & ARGT_MASK) {
			case ARGT_UINT: argp[idx].type = mask & ARGT_MASK; break;
			case ARGT_TIME: argp[idx].type = mask & ARGT_MASK; break;
			case ARGT_SIZE: argp[idx].type = mask & ARGT_MASK; break;
			}
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
 * They run with the tree head "hlua_ctx", they just perform lookup in the
 * tree.
 *
 *  - hlua_gethlua : return the hlua context associated with an lua_State.
 *  - hlua_delhlua : remove the association between hlua context and lua_state.
 *  - hlua_sethlua : create the association between hlua context and lua_state.
 */
static inline struct hlua *hlua_gethlua(lua_State *L)
{
	struct ebpt_node *node;

	node = ebpt_lookup(&hlua_ctx, L);
	if (!node)
		return NULL;
	return ebpt_entry(node, struct hlua, node);
}
static inline void hlua_delhlua(struct hlua *hlua)
{
	if (hlua->node.key)
		ebpt_delete(&hlua->node);
}
static inline void hlua_sethlua(struct hlua *hlua)
{
	hlua->node.key = hlua->T;
	ebpt_insert(&hlua_ctx, &hlua->node);
}

/* This function initialises the Lua environment stored in the session.
 * It must be called at the start of the session. This function creates
 * an LUA coroutine. It can not be use to crete the main LUA context.
 */
int hlua_ctx_init(struct hlua *lua, struct task *task)
{
	lua->Mref = LUA_REFNIL;
	lua->state = HLUA_STOP;
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

/* Used to destroy the Lua coroutine when the attached session or task
 * is destroyed. The destroy also the memory context. The struct "lua"
 * is not freed.
 */
void hlua_ctx_destroy(struct hlua *lua)
{
	/* Remove context. */
	hlua_delhlua(lua);

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

	/* Remove context. */
	hlua_delhlua(lua);

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

	lua->state = HLUA_RUN;

	/* Call the function. */
	ret = lua_resume(lua->T, gL.T, lua->nargs);
	switch (ret) {

	case LUA_OK:
		ret = HLUA_E_OK;
		break;

	case LUA_YIELD:
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
		lua_settop(lua->T, 0); /* Empty the stack. */
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		lua_pushfstring(lua->T, "out of memory error");
		ret = HLUA_E_ERRMSG;
		break;

	case LUA_ERRERR:
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
		lua->state = HLUA_STOP;
		break;

	case HLUA_E_ERR:
		lua->state = HLUA_STOP;
		hlua_com_purge(lua);
		hlua_ctx_renew(lua, 0);
		break;

	case HLUA_E_OK:
		lua->state = HLUA_STOP;
		hlua_com_purge(lua);
		break;
	}

	return ret;
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
 * Class TXN
 *
 *
 */

/* Returns a struct hlua_session if the stack entry "ud" is
 * a class session, otherwise it throws an error.
 */
__LJMP static struct hlua_txn *hlua_checktxn(lua_State *L, int ud)
{
	return (struct hlua_txn *)MAY_LJMP(hlua_checkudata(L, ud, class_txn_ref));
}

__LJMP static int hlua_setpriv(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "set_priv"));

	/* It is useles to retrieve the session, but this function
	 * runs only in a session context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));
	struct hlua *hlua = hlua_gethlua(L);

	/* Remove previous value. */
	if (hlua->Mref != -1)
		luaL_unref(L, hlua->Mref, LUA_REGISTRYINDEX);

	/* Get and store new value. */
	lua_pushvalue(L, 2); /* Copy the element 2 at the top of the stack. */
	hlua->Mref = luaL_ref(L, LUA_REGISTRYINDEX); /* pop the previously pushed value. */

	return 0;
}

__LJMP static int hlua_getpriv(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "get_priv"));

	/* It is useles to retrieve the session, but this function
	 * runs only in a session context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));
	struct hlua *hlua = hlua_gethlua(L);

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* Create stack entry containing a class TXN. This function
 * return 0 if the stack does not contains free slots,
 * otherwise it returns 1.
 */
static int hlua_txn_new(lua_State *L, struct session *s, struct proxy *p, void *l7)
{
	struct hlua_txn *hs;

	/* Check stack size. */
	if (!lua_checkstack(L, 2))
		return 0;

	/* NOTE: The allocation never fails. The failure
	 * throw an error, and the function never returns.
	 * if the throw is not avalaible, the process is aborted.
	 */
	hs = lua_newuserdata(L, sizeof(struct hlua_txn));
	hs->s = s;
	hs->p = p;
	hs->l7 = l7;

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_txn_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function is an LUA binding. It is called with each sample-fetch.
 * It uses closure argument to store the associated sample-fetch. It
 * returns only one argument or throws an error. An error is throwed
 * only if an error is encoutered during the argument parsing. If
 * the "sample-fetch" function fails, nil is returned.
 */
__LJMP static int hlua_run_sample_fetch(lua_State *L)
{
	struct hlua_txn *s;
	struct hlua_sample_fetch *f;
	struct arg args[ARGM_NBARGS];
	int i;
	struct sample smp;

	/* Get closure arguments. */
	f = (struct hlua_sample_fetch *)lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditionnal arguments. */
	s = MAY_LJMP(hlua_checktxn(L, 1));

	/* Get extra arguments. */
	for (i = 0; i <= lua_gettop(L); i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 2, &args[i]);
	}
	args[i].type = ARGT_STOP;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 1, args, f->f->arg_mask));

	/* Run the special args cehcker. */
	if (!f->f->val_args(args, NULL)) {
		lua_pushfstring(L, "error in arguments");
		WILL_LJMP(lua_error(L));
	}

	/* Initialise the sample. */
	memset(&smp, 0, sizeof(smp));

	/* Run the sample fetch process. */
	if (!f->f->process(s->p, s->s, s->l7, 0, args, &smp, f->f->kw, f->f->private)) {
		lua_pushnil(L);
		return 1;
	}

	/* Convert the returned sample in lua value. */
	hlua_smp2lua(L, &smp);
	return 1;
}

/* This function is an LUA binding. It creates ans returns
 * an array of HTTP headers. This function does not fails.
 */
static int hlua_session_getheaders(lua_State *L)
{
	struct hlua_txn *s = MAY_LJMP(hlua_checktxn(L, 1));
	struct session *sess = s->s;
	const char *cur_ptr, *cur_next, *p;
	int old_idx, cur_idx;
	struct hdr_idx_elem *cur_hdr;
	const char *hn, *hv;
	int hnl, hvl;

	/* Create the table. */
	lua_newtable(L);

	/* Build array of headers. */
	old_idx = 0;
	cur_next = sess->req->buf->p + hdr_idx_first_pos(&sess->txn.hdr_idx);

	while (1) {
		cur_idx = sess->txn.hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;
		old_idx = cur_idx;

		cur_hdr  = &sess->txn.hdr_idx.v[cur_idx];
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

		/* Push values in the table. */
		lua_pushlstring(L, hn, hnl);
		lua_pushlstring(L, hv, hvl);
		lua_settable(L, -3);
	}

	return 1;
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

	/* Execute the Lua code. */
	status = hlua_ctx_resume(hlua, 1);

	switch (status) {
	/* finished or yield */
	case HLUA_E_OK:
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;

	case HLUA_E_AGAIN: /* co process wake me later. */
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
static int hlua_sample_conv_wrapper(struct session *session, const struct arg *arg_p,
                                    struct sample *smp, void *private)
{
	struct hlua_function *fcn = (struct hlua_function *)private;

	/* If it is the first run, initialize the data for the call. */
	if (session->hlua.state == HLUA_STOP) {
		/* Check stack available size. */
		if (!lua_checkstack(session->hlua.T, 1)) {
			send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(session->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* convert input sample and pust-it in the stack. */
		if (!lua_checkstack(session->hlua.T, 1)) {
			send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}
		hlua_smp2lua(session->hlua.T, smp);
		session->hlua.nargs = 2;

		/* push keywords in the stack. */
		if (arg_p) {
			for (; arg_p->type != ARGT_STOP; arg_p++) {
				if (!lua_checkstack(session->hlua.T, 1)) {
					send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
					if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
						Alert("Lua converter '%s': full stack.\n", fcn->name);
					return 0;
				}
				hlua_arg2lua(session->hlua.T, arg_p);
				session->hlua.nargs++;
			}
		}

		/* Set the currently running flag. */
		session->hlua.state = HLUA_RUN;
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&session->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(session->hlua.T, -1, smp);
		lua_pop(session->hlua.T, 1);
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(session->be, LOG_ERR, "Lua converter '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(session->be, LOG_ERR, "Lua converter '%s': %s.", fcn->name, lua_tostring(session->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': %s.\n", fcn->name, lua_tostring(session->hlua.T, -1));
		lua_pop(session->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(session->be, LOG_ERR, "Lua converter '%s' returns an unknown error.", fcn->name);
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
static int hlua_sample_fetch_wrapper(struct proxy *px, struct session *s, void *l7,
                                     unsigned int opt, const struct arg *arg_p,
                                     struct sample *smp, const char *kw, void *private)
{
	struct hlua_function *fcn = (struct hlua_function *)private;

	/* If it is the first run, initialize the data for the call. */
	if (s->hlua.state == HLUA_STOP) {
		/* Check stack available size. */
		if (!lua_checkstack(s->hlua.T, 2)) {
			send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(s->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* push arguments in the stack. */
		if (!hlua_txn_new(s->hlua.T, s, px, l7)) {
			send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}
		s->hlua.nargs = 1;

		/* push keywords in the stack. */
		for (; arg_p && arg_p->type != ARGT_STOP; arg_p++) {
			/* Check stack available size. */
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			hlua_arg2lua(s->hlua.T, arg_p);
			s->hlua.nargs++;
		}

		/* Set the currently running flag. */
		s->hlua.state = HLUA_RUN;
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&s->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(s->hlua.T, -1, smp);
		lua_pop(s->hlua.T, 1);

		/* Set the end of execution flag. */
		smp->flags &= ~SMP_F_MAY_CHANGE;
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(px, LOG_ERR, "Lua sample-fetch '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua sample-fetch '%s': %s.", fcn->name, lua_tostring(s->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': %s.\n", fcn->name, lua_tostring(s->hlua.T, -1));
		lua_pop(s->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua sample-fetch '%s' returns an unknown error.", fcn->name);
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
	sck = malloc(sizeof(struct sample_conv_kw_list) +
	             sizeof(struct sample_conv) * 2);
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
	sfk = malloc(sizeof(struct sample_fetch_kw_list) +
	             sizeof(struct sample_fetch) * 2);
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
	{ CFG_GLOBAL, "lua-load",  hlua_load },
	{ 0, NULL, NULL },
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

void hlua_init(void)
{
	int i;
	int idx;
	struct sample_fetch *sf;
	struct hlua_sample_fetch *hsf;
	char *p;

	/* Initialise com signals pool session. */
	pool2_hlua_com = create_pool("hlua_com", sizeof(struct hlua_com), MEM_F_SHARED);

	/* Register configuration keywords. */
	cfg_register_keywords(&cfg_kws);

	/* Init main lua stack. */
	gL.Mref = LUA_REFNIL;
	gL.state = HLUA_STOP;
	LIST_INIT(&gL.com);
	gL.T = luaL_newstate();
	hlua_sethlua(&gL);
	gL.Tref = LUA_REFNIL;
	gL.task = NULL;

	/* Initialise lua. */
	luaL_openlibs(gL.T);

	/*
	 *
	 * Create "core" object.
	 *
	 */

	/* This integer entry is just used as base value for the object "core". */
	lua_pushinteger(gL.T, 0);

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fill the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Push the loglevel constants. */
	for (i=0; i<NB_LOG_LEVELS; i++)
		hlua_class_const_int(gL.T, log_levels[i], i);

	/* Register special functions. */
	hlua_class_function(gL.T, "register_init", hlua_register_init);
	hlua_class_function(gL.T, "register_task", hlua_register_task);
	hlua_class_function(gL.T, "register_fetches", hlua_register_fetches);
	hlua_class_function(gL.T, "register_converters", hlua_register_converters);

	/* Store the table __index in the metable. */
	lua_settable(gL.T, -3);

	/* Register previous table in the registry with named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_CORE); /* register class session. */

	/* Register previous table in the registry with reference. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	class_core_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/* Create new object with class Core. */
	lua_setmetatable(gL.T, -2);
	lua_setglobal(gL.T, "core");

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
		hsf = lua_newuserdata(gL.T, sizeof(struct hlua_sample_fetch));
		hsf->f = sf;
		lua_pushcclosure(gL.T, hlua_run_sample_fetch, 1);
		lua_settable(gL.T, -3);
	}

	/* Register Lua functions. */
	hlua_class_function(gL.T, "get_headers", hlua_session_getheaders);
	hlua_class_function(gL.T, "set_priv",    hlua_setpriv);
	hlua_class_function(gL.T, "get_priv",    hlua_getpriv);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_TXN); /* register class session. */
	class_txn_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */
}
