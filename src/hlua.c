#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

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

void hlua_init(void)
{
}
