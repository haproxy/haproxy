#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <ebpttree.h>

#include <common/cfgparse.h>

#include <types/hlua.h>
#include <types/proxy.h>

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

/* Store the fast lua context for coroutines. This tree uses the
 * Lua stack pointer value as indexed entry, and store the associated
 * hlua context.
 */
struct eb_root hlua_ctx = EB_ROOT_UNIQUE;

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
		hlua_ctx_renew(lua, 1);
		lua->state = HLUA_STOP;
		break;

	case HLUA_E_ERR:
		lua->state = HLUA_STOP;
		hlua_ctx_renew(lua, 0);
		break;

	case HLUA_E_OK:
		lua->state = HLUA_STOP;
		break;
	}

	return ret;
}

void hlua_init(void)
{
	/* Init main lua stack. */
	gL.Mref = LUA_REFNIL;
	gL.state = HLUA_STOP;
	gL.T = luaL_newstate();
	hlua_sethlua(&gL);
	gL.Tref = LUA_REFNIL;
	gL.task = NULL;

	/* Initialise lua. */
	luaL_openlibs(gL.T);
}
