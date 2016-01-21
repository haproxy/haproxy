/* All the functions in this file runs with aLua stack, and can
 * return with a longjmp. All of these function must be launched
 * in an environment able to catch a longjmp, otherwise a
 * critical error can be raised.
 */
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

static void hlua_array_add_fcn(lua_State *L, const char *name,
                               int (*function)(lua_State *L))
{
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_rawset(L, -3);
}

int hlua_fcn_reg_core_fcn(lua_State *L)
{
	return 0;
}
