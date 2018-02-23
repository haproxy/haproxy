/* spoa-server: processing Lua
 *
 * Copyright 2018 OZON / Thierry Fournier <thierry.fournier@ozon.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "spoa.h"

static lua_State *L = NULL;
static struct worker *worker;

static int ps_lua_start_worker(struct worker *w);
static int ps_lua_load_file(struct worker *w, const char *file);
static int ps_lua_exec_message(struct worker *w, void *ref, int nargs, struct spoe_kv *args);

static struct ps ps_lua_bindings_1 = {
	.init_worker = ps_lua_start_worker,
	.load_file = ps_lua_load_file,
	.exec_message = ps_lua_exec_message,
	.ext = ".lua",
};

static struct ps ps_lua_bindings_2 = {
	.init_worker = ps_lua_start_worker,
	.load_file = ps_lua_load_file,
	.exec_message = ps_lua_exec_message,
	.ext = ".luac",
};

/* Imported from Lua-5.3.4 */
static int typeerror (lua_State *L, int arg, const char *tname)
{
	const char *msg;
	const char *typearg;  /* name for the type of the actual argument */
	if (luaL_getmetafield(L, arg, "__name") == LUA_TSTRING)
		typearg = lua_tostring(L, -1);  /* use the given type name */
	else if (lua_type(L, arg) == LUA_TLIGHTUSERDATA)
		typearg = "light userdata";  /* special name for messages */
	else
		typearg = luaL_typename(L, arg);  /* standard name */
	msg = lua_pushfstring(L, "%s expected, got %s", tname, typearg);
	return luaL_argerror(L, arg, msg);
}

/* Imported from Lua-5.3.4 */
static void tag_error (lua_State *L, int arg, int tag) {
	typeerror(L, arg, lua_typename(L, tag));
}

#ifndef luaL_checkboolean
static int luaL_checkboolean(lua_State *L, int index)
{
	if (!lua_isboolean(L, index)) {
		tag_error(L, index, LUA_TBOOLEAN);
	}
	return lua_toboolean(L, index);
}
#endif

static int ps_lua_register_message(lua_State *L)
{
	const char *name;
	long ref;

	/* First argument is a message name */
	name = luaL_checkstring(L, 1);

	/* Second argument is a function */
	if (!lua_isfunction(L, 2)) {
		const char *msg = lua_pushfstring(L, "function expected, got %s", luaL_typename(L, 2));
		luaL_argerror(L, 2, msg);
	}
	lua_pushvalue(L, 2);
	ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Register the message processor */
	ps_register_message(&ps_lua_bindings_1, name, (void *)ref);

	return 1;
}

static int ps_lua_set_var_null(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);

	if (!set_var_null(worker, name, name_len, scope)) {
		luaL_error(L, "No space left available");
	}
	return 0;
}

static int ps_lua_set_var_boolean(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	int64_t value;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkboolean(L, 3);

	if (!set_var_bool(worker, name, name_len, scope, value))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_uint32(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	int64_t value;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkinteger(L, 3);

	if (value < 0 || value > UINT_MAX)
		luaL_error(L, "Integer '%lld' out of range for 'uint32' type", value);

	if (!set_var_uint32(worker, name, name_len, scope, value))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_int32(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	int64_t value;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkinteger(L, 3);

	if (value < INT_MIN || value > INT_MAX)
		luaL_error(L, "Integer '%lld' out of range for 'int32' type", value);

	if (!set_var_int32(worker, name, name_len, scope, value))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_uint64(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	int64_t value;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkinteger(L, 3);

	if (value < 0)
		luaL_error(L, "Integer '%lld' out of range for 'uint64' type", value);

	if (!set_var_uint64(worker, name, name_len, scope, value))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_int64(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	int64_t value;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkinteger(L, 3);

	if (!set_var_int64(worker, name, name_len, scope, value))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_ipv4(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	const char *value;
	struct in_addr ipv4;
	int ret;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkstring(L, 3);

	ret = inet_pton(AF_INET, value, &ipv4);
	if (ret == 0)
		luaL_error(L, "IPv4 '%s': invalid format", value);
	if (ret == -1)
		luaL_error(L, "IPv4 '%s': %s", value, strerror(errno));

	if (!set_var_ipv4(worker, name, name_len, scope, &ipv4))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_ipv6(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	const char *value;
	struct in6_addr ipv6;
	int ret;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checkstring(L, 3);

	ret = inet_pton(AF_INET6, value, &ipv6);
	if (ret == 0)
		luaL_error(L, "IPv6 '%s': invalid format", value);
	if (ret == -1)
		luaL_error(L, "IPv6 '%s': %s", value, strerror(errno));

	if (!set_var_ipv6(worker, name, name_len, scope, &ipv6))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_str(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	const char *value;
	size_t value_len;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checklstring(L, 3, &value_len);

	if (!set_var_string(worker, name, name_len, scope, value, value_len))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_set_var_bin(lua_State *L)
{
	const char *name;
	size_t name_len;
	unsigned char scope;
	const char *value;
	size_t value_len;

	name = luaL_checklstring(L, 1, &name_len);
	scope = (unsigned char)luaL_checkinteger(L, 2);
	value = luaL_checklstring(L, 3, &value_len);

	if (!set_var_bin(worker, name, name_len, scope, value, value_len))
		luaL_error(L, "No space left available");
	return 0;
}

static int ps_lua_start_worker(struct worker *w)
{
	if (L != NULL)
		return 1;

	worker = w;

	L = luaL_newstate();
	luaL_openlibs(L);

	lua_newtable(L);

	lua_pushstring(L, "register_message");
	lua_pushcclosure(L, ps_lua_register_message, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_null");
	lua_pushcclosure(L, ps_lua_set_var_null, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_boolean");
	lua_pushcclosure(L, ps_lua_set_var_boolean, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_uint32");
	lua_pushcclosure(L, ps_lua_set_var_uint32, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_int32");
	lua_pushcclosure(L, ps_lua_set_var_int32, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_uint64");
	lua_pushcclosure(L, ps_lua_set_var_uint64, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_int64");
	lua_pushcclosure(L, ps_lua_set_var_int64, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_ipv4");
	lua_pushcclosure(L, ps_lua_set_var_ipv4, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_ipv6");
	lua_pushcclosure(L, ps_lua_set_var_ipv6, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_str");
	lua_pushcclosure(L, ps_lua_set_var_str, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "set_var_bin");
	lua_pushcclosure(L, ps_lua_set_var_bin, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "scope");
	lua_newtable(L);

	lua_pushstring(L, "proc");
	lua_pushinteger(L, SPOE_SCOPE_PROC);
	lua_rawset(L, -3);

	lua_pushstring(L, "sess");
	lua_pushinteger(L, SPOE_SCOPE_SESS);
	lua_rawset(L, -3);

	lua_pushstring(L, "txn");
	lua_pushinteger(L, SPOE_SCOPE_TXN);
	lua_rawset(L, -3);

	lua_pushstring(L, "req");
	lua_pushinteger(L, SPOE_SCOPE_REQ);
	lua_rawset(L, -3);

	lua_pushstring(L, "res");
	lua_pushinteger(L, SPOE_SCOPE_RES);
	lua_rawset(L, -3);

	lua_rawset(L, -3); /* scope */

	lua_setglobal(L, "spoa");
	return 1;
}

static int ps_lua_load_file(struct worker *w, const char *file)
{
	int error;

	/* Load the file and check syntax */
	error = luaL_loadfile(L, file);
	if (error) {
		fprintf(stderr, "lua syntax error: %s\n", lua_tostring(L, -1));
		return 0;
	}

	/* If no syntax error where detected, execute the code. */
	error = lua_pcall(L, 0, LUA_MULTRET, 0);
   switch (error) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		fprintf(stderr, "lua runtime error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return 0;
	case LUA_ERRMEM:
		fprintf(stderr, "lua out of memory error\n");
		return 0;
	case LUA_ERRERR:
		fprintf(stderr, "lua message handler error: %s\n", lua_tostring(L, 0));
		lua_pop(L, 1);
		return 0;
	case LUA_ERRGCMM:
		fprintf(stderr, "lua garbage collector error: %s\n", lua_tostring(L, 0));
		lua_pop(L, 1);
		return 0;
	default:
		fprintf(stderr, "lua unknonwn error: %s\n", lua_tostring(L, 0));
		lua_pop(L, 1);
		return 0;
	}
	return 1;
}

static int ps_lua_exec_message(struct worker *w, void *ref, int nargs, struct spoe_kv *args)
{
	long lua_ref = (long)ref;
	int ret;
	char *msg_fmt = NULL;
	const char *msg;
	int i;
	char ipbuf[64];

	/* Restore function in the stack */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_ref);

	/* convert args in lua mode */
	lua_newtable(L);
	for (i = 0; i < nargs; i++) {
		lua_newtable(L);
		lua_pushstring(L, "name");
		lua_pushlstring(L, args[i].name.str, args[i].name.len);
		lua_rawset(L, -3); /* Push name */
		lua_pushstring(L, "value");
		switch (args[i].value.type) {
		case SPOE_DATA_T_NULL:
			lua_pushnil(L);
			break;
		case SPOE_DATA_T_BOOL:
			lua_pushboolean(L, args[i].value.u.boolean);
			break;
		case SPOE_DATA_T_INT32:
			lua_pushinteger(L, args[i].value.u.sint32);
			break;
		case SPOE_DATA_T_UINT32:
			lua_pushinteger(L, args[i].value.u.uint32);
			break;
		case SPOE_DATA_T_INT64:
			lua_pushinteger(L, args[i].value.u.sint64);
			break;
		case SPOE_DATA_T_UINT64:
			if (args[i].value.u.uint64 > LLONG_MAX)
				lua_pushnil(L);
			else
				lua_pushinteger(L, args[i].value.u.uint64);
			break;
		case SPOE_DATA_T_IPV4:
			if (inet_ntop(AF_INET, &args[i].value.u.ipv4, ipbuf, 64) == NULL)
				lua_pushnil(L);
			else
				lua_pushstring(L, ipbuf);
			break;
		case SPOE_DATA_T_IPV6:
			if (inet_ntop(AF_INET6, &args[i].value.u.ipv4, ipbuf, 64) == NULL)
				lua_pushnil(L);
			else
				lua_pushstring(L, ipbuf);
			break;
		case SPOE_DATA_T_STR:
		case SPOE_DATA_T_BIN:
			lua_pushlstring(L, args[i].value.u.buffer.str, args[i].value.u.buffer.len);
			break;
		default:
			lua_pushnil(L);
			break;
		}
		lua_rawset(L, -3); /* Push name */
		lua_rawseti(L, -2, i + 1); /* Pusg table in globale table */
	}

	/* execute lua function */
	while (1) {
		ret = lua_resume(L, L, 1);
		switch (ret) {
		case LUA_OK:
			return 1;
		case LUA_YIELD:
			DEBUG("Lua yield");
			continue;
		case LUA_ERRMEM:
			LOG("Lua: Out of memory error");
			return 0;
		case LUA_ERRRUN:
			msg_fmt = "Lua runtime error";
		case LUA_ERRGCMM:
			msg_fmt = msg_fmt ? msg_fmt : "Lua garbage collector error";
		case LUA_ERRERR:
			msg_fmt = msg_fmt ? msg_fmt : "Lua message handler error";
		default:
			msg_fmt = msg_fmt ? msg_fmt : "Lua unknonwn error";
			msg = lua_tostring(L, -1);
			if (msg == NULL)
				msg = "Unknown error";
			LOG("%s: %s", msg_fmt, msg);
			lua_settop(L, 0);
			return 0;
		}
	}

	return 1;
}

__attribute__((constructor))
static void __ps_lua_init(void)
{
	ps_register(&ps_lua_bindings_1);
	ps_register(&ps_lua_bindings_2);
}
