/* All the functions in this file runs with aLua stack, and can
 * return with a longjmp. All of these function must be launched
 * in an environment able to catch a longjmp, otherwise a
 * critical error can be raised.
 */
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <common/time.h>

/* This function return the current date at epoch format in milliseconds. */
int hlua_now(lua_State *L)
{
	lua_newtable(L);
	lua_pushstring(L, "sec");
	lua_pushinteger(L, now.tv_sec);
	lua_rawset(L, -3);
	lua_pushstring(L, "usec");
	lua_pushinteger(L, now.tv_usec);
	lua_rawset(L, -3);
	return 1;
}

/* This functions expects a Lua string as HTTP date, parse it and
 * returns an integer containing the epoch format of the date, or
 * nil if the parsing fails.
 */
static int hlua_parse_date(lua_State *L, int (*fcn)(const char *, int, struct tm*))
{
	const char *str;
	size_t len;
	struct tm tm;
	time_t time;

	str = luaL_checklstring(L, 1, &len);

	if (!fcn(str, len, &tm)) {
		lua_pushnil(L);
		return 1;
	}

	/* This function considers the content of the broken-down time
	 * is exprimed in the UTC timezone. timegm don't care about
	 * the gnu variable tm_gmtoff. If gmtoff is set, or if you know
	 * the timezone from the broken-down time, it must be fixed
	 * after the conversion.
	 */
	time = timegm(&tm);
	if (time == -1) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, (int)time);
	return 1;
}
static int hlua_http_date(lua_State *L)
{
	return hlua_parse_date(L, parse_http_date);
}
static int hlua_imf_date(lua_State *L)
{
	return hlua_parse_date(L, parse_imf_date);
}
static int hlua_rfc850_date(lua_State *L)
{
	return hlua_parse_date(L, parse_rfc850_date);
}
static int hlua_asctime_date(lua_State *L)
{
	return hlua_parse_date(L, parse_asctime_date);
}

static void hlua_array_add_fcn(lua_State *L, const char *name,
                               int (*function)(lua_State *L))
{
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_rawset(L, -3);
}

int hlua_fcn_reg_core_fcn(lua_State *L)
{
	hlua_array_add_fcn(L, "now", hlua_now);
	hlua_array_add_fcn(L, "http_date", hlua_http_date);
	hlua_array_add_fcn(L, "imf_date", hlua_imf_date);
	hlua_array_add_fcn(L, "rfc850_date", hlua_rfc850_date);
	hlua_array_add_fcn(L, "asctime_date", hlua_asctime_date);
	return 5;
}
