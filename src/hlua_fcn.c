/*
 * Lua safe functions
 *
 * Copyright 2015-2016 Thierry Fournier <tfournier@arpalert.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 *
 * All the functions in this file runs with a Lua stack, and can
 * return with a longjmp. All of these function must be launched
 * in an environment able to catch a longjmp, otherwise a
 * critical error can be raised.
 */
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <common/time.h>
#include <common/uri_auth.h>

#include <types/hlua.h>
#include <types/proxy.h>

#include <proto/dumpstats.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/server.h>

/* Contains the class reference of the concat object. */
static int class_concat_ref;
static int class_proxy_ref;
static int class_server_ref;
static int class_listener_ref;

#define STATS_LEN (MAX((int)ST_F_TOTAL_FIELDS, (int)INF_TOTAL_FIELDS))

static struct field stats[STATS_LEN];

/* This function gets a struct field and convert it in Lua
 * variable. The variable is pushed at the top of the stak.
 */
int hlua_fcn_pushfield(lua_State *L, struct field *field)
{
	/* The lua_Integer is always signed. Its length depends on
	 * compilation opions, so the followinfg code is conditionned
	 * by some macros. Windows maros are not supported.
	 * If the number cannot be represented as integer, we try to
	 * convert to float.
	 */
	switch (field_format(field, 0)) {

	case FF_EMPTY:
		lua_pushnil(L);
		return 1;

	case FF_S32:
		/* S32 is always supported. */
		lua_pushinteger(L, field->u.s32);
		return 1;

	case FF_U32:
#if (LUA_MAXINTEGER == LLONG_MAX || ((LUA_MAXINTEGER == LONG_MAX) && (__WORDSIZE == 64)))
		/* 64 bits case, U32 is always supported */
		lua_pushinteger(L, field->u.u32);
#else
		/* 32 bits case, U32 is supported until INT_MAX. */
		if (field->u.u32 > INT_MAX)
			lua_pushnumber(L, (lua_Number)field->u.u32);
		else
			lua_pushinteger(L, field->u.u32);
#endif
		return 1;

	case FF_S64:
#if (LUA_MAXINTEGER == LLONG_MAX || ((LUA_MAXINTEGER == LONG_MAX) && (__WORDSIZE == 64)))
		/* 64 bits case, S64 is always supported */
		lua_pushinteger(L, field->u.s64);
#else
		/* 64 bits case, S64 is supported beetween INT_MIN and INT_MAX */
		if (field->u.s64 < INT_MIN || field->u.s64 > INT_MAX)
			lua_pushnumber(L, (lua_Number)field->u.s64);
		else
			lua_pushinteger(L, (int)field->u.s64);
#endif
		return 1;

	case FF_U64:
#if (LUA_MAXINTEGER == LLONG_MAX || ((LUA_MAXINTEGER == LONG_MAX) && (__WORDSIZE == 64)))
		/* 64 bits case, U64 is supported until LLONG_MAX */
		if (field->u.u64 > LLONG_MAX)
			lua_pushnumber(L, (lua_Number)field->u.u64);
		else
			lua_pushinteger(L, field->u.u64);
#else
		/* 64 bits case, U64 is supported until INT_MAX */
		if (field->u.u64 > INT_MAX)
			lua_pushnumber(L, (lua_Number)field->u.u64);
		else
			lua_pushinteger(L, (int)field->u.u64);
#endif
		return 1;

	case FF_STR:
		lua_pushstring(L, field->u.str);
		return 1;

	default:
		break;
	}

	/* Default case, never reached. */
	lua_pushnil(L);
	return 1;
}

/* Some string are started or terminated by blank chars,
 * this function removes the spaces, tabs, \r and
 * \n at the begin and at the end of the string "str", and
 * push the result in the lua stack.
 * Returns a pointer to the Lua internal copy of the string.
 */
const char *hlua_pushstrippedstring(lua_State *L, const char *str)
{
	const char *p;
	const char *e;

	for (p = str; HTTP_IS_LWS(*p); p++);
	for (e = p + strlen(p) - 1; e > p && HTTP_IS_LWS(*e); e--);

	return lua_pushlstring(L, p, e - p);
}

/* The three following functions are useful for adding entries
 * in a table. These functions takes a string and respectively an
 * integer, a string or a function and add it to the table in the
 * top of the stack.
 *
 * These functions throws an error if no more stack size is
 * available.
 */
void hlua_class_const_int(lua_State *L, const char *name, int value)
{
	lua_pushstring(L, name);
	lua_pushinteger(L, value);
	lua_rawset(L, -3);
}
void hlua_class_const_str(lua_State *L, const char *name, const char *value)
{
	lua_pushstring(L, name);
	lua_pushstring(L, value);
	lua_rawset(L, -3);
}
void hlua_class_function(lua_State *L, const char *name, int (*function)(lua_State *L))
{
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_rawset(L, -3);
}

/* This function returns a string containg the HAProxy object name. */
int hlua_dump_object(struct lua_State *L)
{
	const char *name = (const char *)lua_tostring(L, lua_upvalueindex(1));
	lua_pushfstring(L, "HAProxy class %s", name);
	return 1;
}

/* This function register a table as metatable and. It names
 * the metatable, and returns the associated reference.
 * The original table is poped from the top of the stack.
 * "name" is the referenced class name.
 */
int hlua_register_metatable(struct lua_State *L, char *name)
{
	/* Check the type of the top element. it must be
	 * a table.
	 */
	if (lua_type(L, -1) != LUA_TTABLE)
		luaL_error(L, "hlua_register_metatable() requires a type Table "
		              "in the top of the stack");

	/* Add the __tostring function which identify the
	 * created object.
	 */
	lua_pushstring(L, "__tostring");
	lua_pushstring(L, name);
	lua_pushcclosure(L, hlua_dump_object, 1);
	lua_rawset(L, -3);

	/* Register a named entry for the table. The table
	 * reference is copyed first because the function
	 * lua_setfield() pop the entry.
	 */
	lua_pushvalue(L, -1);
	lua_setfield(L, LUA_REGISTRYINDEX, name);

	/* Creates the reference of the object. The
	 * function luaL_ref pop the top of the stack.
	 */
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* Return an object of the expected type, or throws an error. */
void *hlua_checkudata(lua_State *L, int ud, int class_ref)
{
	void *p;
	int ret;

	/* Check if the stack entry is an array. */
	if (!lua_istable(L, ud))
		luaL_argerror(L, ud, NULL);

	/* pop the metatable of the referencecd object. */
	if (!lua_getmetatable(L, ud))
		luaL_argerror(L, ud, NULL);

	/* pop the expected metatable. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_ref);

	/* Check if the metadata have the expected type. */
	ret = lua_rawequal(L, -1, -2);
	lua_pop(L, 2);
	if (!ret)
		luaL_argerror(L, ud, NULL);

	/* Push on the stack at the entry [0] of the table. */
	lua_rawgeti(L, ud, 0);

	/* Check if this entry is userdata. */
	p = lua_touserdata(L, -1);
	if (!p)
		luaL_argerror(L, ud, NULL);

	/* Remove the entry returned by lua_rawgeti(). */
	lua_pop(L, 1);

	/* Return the associated struct. */
	return p;
}

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

static int hlua_get_info(lua_State *L)
{
	int i;

	stats_fill_info(stats, STATS_LEN);

	lua_newtable(L);
	for (i=0; i<INF_TOTAL_FIELDS; i++) {
		lua_pushstring(L, info_field_names[i]);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;
}

static struct hlua_concat *hlua_check_concat(lua_State *L, int ud)
{
	return (hlua_checkudata(L, ud, class_concat_ref));
}

static int hlua_concat_add(lua_State *L)
{
	struct hlua_concat *b;
	char *buffer;
	char *new;
	const char *str;
	size_t l;

	/* First arg must be a concat object. */
	b = hlua_check_concat(L, 1);

	/* Second arg must be a string. */
	str = luaL_checklstring(L, 2, &l);

	/* Get the buffer. */
	lua_rawgeti(L, 1, 1);
	buffer = lua_touserdata(L, -1);
	lua_pop(L, 1);

	/* Update the buffer size if it s required. The old buffer
	 * is crushed by the new in the object array, so it will
	 * be deleted by the GC.
	 * Note that in the first loop, the "new" variable is only
	 * used as a flag.
	 */
	new = NULL;
	while (b->size - b->len < l) {
		b->size += HLUA_CONCAT_BLOCSZ;
		new = buffer;
	}
	if (new) {
		new = lua_newuserdata(L, b->size);
		memcpy(new, buffer, b->len);
		lua_rawseti(L, 1, 1);
		buffer = new;
	}

	/* Copy string, and update metadata. */
	memcpy(buffer + b->len, str, l);
	b->len += l;
	return 0;
}

static int hlua_concat_dump(lua_State *L)
{
	struct hlua_concat *b;
	char *buffer;

	/* First arg must be a concat object. */
	b = hlua_check_concat(L, 1);

	/* Get the buffer. */
	lua_rawgeti(L, 1, 1);
	buffer = lua_touserdata(L, -1);
	lua_pop(L, 1);

	/* Push the soncatenated strng in the stack. */
	lua_pushlstring(L, buffer, b->len);
	return 1;
}

int hlua_concat_new(lua_State *L)
{
	struct hlua_concat *b;

	lua_newtable(L);
	b = lua_newuserdata(L, sizeof(*b));
	b->size = HLUA_CONCAT_BLOCSZ;
	b->len = 0;
	lua_rawseti(L, -2, 0);
	lua_newuserdata(L, HLUA_CONCAT_BLOCSZ);
	lua_rawseti(L, -2, 1);

	lua_rawgeti(L, LUA_REGISTRYINDEX, class_concat_ref);
	lua_setmetatable(L, -2);

	return 1;
}

static int concat_tostring(lua_State *L)
{
	const void *ptr = lua_topointer(L, 1);
	lua_pushfstring(L, "Concat object: %p", ptr);
	return 1;
}

static int hlua_concat_init(lua_State *L)
{
	/* Creates the buffered concat object. */
	lua_newtable(L);

	lua_pushstring(L, "__tostring");
	lua_pushcclosure(L, concat_tostring, 0);
	lua_settable(L, -3);

	lua_pushstring(L, "__index"); /* Creates the index entry. */
	lua_newtable(L); /* The "__index" content. */

	lua_pushstring(L, "add");
	lua_pushcclosure(L, hlua_concat_add, 0);
	lua_settable(L, -3);

	lua_pushstring(L, "dump");
	lua_pushcclosure(L, hlua_concat_dump, 0);
	lua_settable(L, -3);

	lua_settable(L, -3); /* Sets the __index entry. */
	class_concat_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	return 1;
}

int hlua_fcn_new_listener(lua_State *L, struct listener *lst)
{
	lua_newtable(L);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_listener_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, lst);
	lua_rawseti(L, -2, 0);
	return 1;
}

static struct listener *hlua_check_listener(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_listener_ref);
}

int hlua_listener_get_stats(lua_State *L)
{
	struct listener *li;
	int i;

	li = hlua_check_listener(L, 1);

	if (!li->frontend) {
		lua_pushnil(L);
		return 1;
	}

	stats_fill_li_stats(li->frontend, li, ST_SHLGNDS, stats, STATS_LEN);

	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_field_names[i]);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;

}

int hlua_fcn_new_server(lua_State *L, struct server *srv)
{
	lua_newtable(L);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_server_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, srv);
	lua_rawseti(L, -2, 0);
	return 1;
}

static struct server *hlua_check_server(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_server_ref);
}

int hlua_server_get_stats(lua_State *L)
{
	struct server *srv;
	int i;

	srv = hlua_check_server(L, 1);

	if (!srv->proxy) {
		lua_pushnil(L);
		return 1;
	}

	stats_fill_sv_stats(srv->proxy, srv, ST_SHLGNDS, stats, STATS_LEN);

	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_field_names[i]);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;

}

int hlua_server_get_addr(lua_State *L)
{
	struct server *srv;
	char addr[INET6_ADDRSTRLEN];
	luaL_Buffer b;

	srv = hlua_check_server(L, 1);

	luaL_buffinit(L, &b);

	switch (srv->addr.ss_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)&srv->addr)->sin_addr,
		          addr, INET_ADDRSTRLEN);
		luaL_addstring(&b, addr);
		luaL_addstring(&b, ":");
		snprintf(addr, INET_ADDRSTRLEN, "%d",
		         ntohs(((struct sockaddr_in *)&srv->addr)->sin_port));
		luaL_addstring(&b, addr);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&srv->addr)->sin6_addr,
		          addr, INET_ADDRSTRLEN);
		luaL_addstring(&b, addr);
		luaL_addstring(&b, ":");
		snprintf(addr, INET_ADDRSTRLEN, "%d",
		         ntohs(((struct sockaddr_in6 *)&srv->addr)->sin6_port));
		luaL_addstring(&b, addr);
		break;
	case AF_UNIX:
		luaL_addstring(&b, (char *)((struct sockaddr_un *)&srv->addr)->sun_path);
		break;
	default:
		luaL_addstring(&b, "<unknown>");
		break;
	}

	luaL_pushresult(&b);
	return 1;
}

int hlua_server_is_draining(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	lua_pushinteger(L, server_is_draining(srv));
	return 1;
}

int hlua_server_set_weight(lua_State *L)
{
	struct server *srv;
	const char *weight;
	const char *err;

	srv = hlua_check_server(L, 1);
	weight = luaL_checkstring(L, 2);

	err = server_parse_weight_change_request(srv, weight);
	if (!err)
		lua_pushnil(L);
	else
		hlua_pushstrippedstring(L, err);
	return 1;
}

int hlua_server_get_weight(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	lua_pushinteger(L, srv->uweight);
	return 1;
}

int hlua_server_set_addr(lua_State *L)
{
	struct server *srv;
	const char *addr;
	const char *err;

	srv = hlua_check_server(L, 1);
	addr = luaL_checkstring(L, 2);

	err = server_parse_addr_change_request(srv, addr, "Lua script");
	if (!err)
		lua_pushnil(L);
	else
		hlua_pushstrippedstring(L, err);
	return 1;
}

int hlua_server_shut_sess(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	srv_shutdown_streams(srv, SF_ERR_KILLED);
	return 0;
}

int hlua_server_set_drain(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	srv_adm_set_drain(srv);
	return 0;
}

int hlua_server_set_maint(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	srv_adm_set_maint(srv);
	return 0;
}

int hlua_server_set_ready(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	srv_adm_set_ready(srv);
	return 0;
}

int hlua_server_check_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->check.state & CHK_ST_CONFIGURED) {
		sv->check.state &= ~CHK_ST_ENABLED;
	}
	return 0;
}

int hlua_server_check_disable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->check.state & CHK_ST_CONFIGURED) {
		sv->check.state |= CHK_ST_ENABLED;
	}
	return 0;
}

int hlua_server_check_force_up(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_running(sv, "changed from Lua script");
	}
	return 0;
}

int hlua_server_check_force_nolb(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_stopping(sv, "changed from Lua script");
	}
	return 0;
}

int hlua_server_check_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (!(sv->track)) {
		sv->check.health = 0;
		srv_set_stopped(sv, "changed from Lua script");
	}
	return 0;
}

int hlua_server_agent_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->agent.state & CHK_ST_CONFIGURED) {
		sv->agent.state |= CHK_ST_ENABLED;
	}
	return 0;
}

int hlua_server_agent_disable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->agent.state & CHK_ST_CONFIGURED) {
		sv->agent.state &= ~CHK_ST_ENABLED;
	}
	return 0;
}

int hlua_server_agent_force_up(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = sv->agent.rise + sv->agent.fall - 1;
		srv_set_running(sv, "changed from Lua script");
	}
	return 0;
}

int hlua_server_agent_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = 0;
		srv_set_stopped(sv, "changed from Lua script");
	}
	return 0;
}

int hlua_fcn_new_proxy(lua_State *L, struct proxy *px)
{
	struct server *srv;
	struct listener *lst;
	int lid;
	char buffer[10];

	lua_newtable(L);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_proxy_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, px);
	lua_rawseti(L, -2, 0);

	/* Browse and register servers. */
	lua_pushstring(L, "servers");
	lua_newtable(L);
	for (srv = px->srv; srv; srv = srv->next) {
		lua_pushstring(L, srv->id);
		hlua_fcn_new_server(L, srv);
		lua_settable(L, -3);
	}
	lua_settable(L, -3);

	/* Browse and register listeners. */
	lua_pushstring(L, "listeners");
	lua_newtable(L);
	lid = 1;
	list_for_each_entry(lst, &px->conf.listeners, by_fe) {
		if (lst->name)
			lua_pushstring(L, lst->name);
		else {
			snprintf(buffer, 10, "sock-%d", lid);
			lid++;
			lua_pushstring(L, buffer);
		}
		hlua_fcn_new_listener(L, lst);
		lua_settable(L, -3);
	}
	lua_settable(L, -3);

	return 1;
}

static struct proxy *hlua_check_proxy(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_proxy_ref);
}

int hlua_proxy_pause(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	pause_proxy(px);
	return 0;
}

int hlua_proxy_resume(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	resume_proxy(px);
	return 0;
}

int hlua_proxy_stop(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	stop_proxy(px);
	return 0;
}

int hlua_proxy_get_cap(lua_State *L)
{
	struct proxy *px;
	const char *str;

	px = hlua_check_proxy(L, 1);
	str = proxy_cap_str(px->cap);
	lua_pushstring(L, str);
	return 1;
}

int hlua_proxy_get_stats(lua_State *L)
{
	struct proxy *px;
	int i;

	px = hlua_check_proxy(L, 1);
	if (px->cap & PR_CAP_BE)
		stats_fill_be_stats(px, ST_SHLGNDS, stats, STATS_LEN);
	else
		stats_fill_fe_stats(px, stats, STATS_LEN);
	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_field_names[i]);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;
}

int hlua_proxy_get_mode(lua_State *L)
{
	struct proxy *px;
	const char *str;

	px = hlua_check_proxy(L, 1);
	str = proxy_mode_str(px->mode);
	lua_pushstring(L, str);
	return 1;
}

int hlua_proxy_shut_bcksess(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	srv_shutdown_backup_streams(px, SF_ERR_KILLED);
	return 0;
}

int hlua_fcn_post_init(lua_State *L)
{
	struct proxy *px;

	/* get core array. */
	if (lua_getglobal(L, "core") != LUA_TTABLE)
		lua_error(L);

	/* Create proxies entry. */
	lua_pushstring(L, "proxies");
	lua_newtable(L);

	/* List all proxies. */
	for (px = proxy; px; px = px->next) {
		lua_pushstring(L, px->id);
		hlua_fcn_new_proxy(L, px);
		lua_settable(L, -3);
	}

	/* push "proxies" in "core" */
	lua_settable(L, -3);

	return 1;
}

int hlua_fcn_reg_core_fcn(lua_State *L)
{
	if (!hlua_concat_init(L))
		return 0;

	hlua_class_function(L, "now", hlua_now);
	hlua_class_function(L, "http_date", hlua_http_date);
	hlua_class_function(L, "imf_date", hlua_imf_date);
	hlua_class_function(L, "rfc850_date", hlua_rfc850_date);
	hlua_class_function(L, "asctime_date", hlua_asctime_date);
	hlua_class_function(L, "concat", hlua_concat_new);
	hlua_class_function(L, "get_info", hlua_get_info);

	/* Create listener object. */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "get_stats", hlua_listener_get_stats);
	lua_settable(L, -3); /* -> META["__index"] = TABLE */
	class_listener_ref = hlua_register_metatable(L, CLASS_LISTENER);

	/* Create server object. */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "is_draining", hlua_server_is_draining);
	hlua_class_function(L, "set_weight", hlua_server_set_weight);
	hlua_class_function(L, "get_weight", hlua_server_get_weight);
	hlua_class_function(L, "set_addr", hlua_server_set_addr);
	hlua_class_function(L, "get_addr", hlua_server_get_addr);
	hlua_class_function(L, "get_stats", hlua_server_get_stats);
	hlua_class_function(L, "shut_sess", hlua_server_shut_sess);
	hlua_class_function(L, "set_drain", hlua_server_set_drain);
	hlua_class_function(L, "set_maint", hlua_server_set_maint);
	hlua_class_function(L, "set_ready", hlua_server_set_ready);
	hlua_class_function(L, "check_enable", hlua_server_check_enable);
	hlua_class_function(L, "check_disable", hlua_server_check_disable);
	hlua_class_function(L, "check_force_up", hlua_server_check_force_up);
	hlua_class_function(L, "check_force_nolb", hlua_server_check_force_nolb);
	hlua_class_function(L, "check_force_down", hlua_server_check_force_down);
	hlua_class_function(L, "agent_enable", hlua_server_agent_enable);
	hlua_class_function(L, "agent_disable", hlua_server_agent_disable);
	hlua_class_function(L, "agent_force_up", hlua_server_agent_force_up);
	hlua_class_function(L, "agent_force_down", hlua_server_agent_force_down);
	lua_settable(L, -3); /* -> META["__index"] = TABLE */
	class_server_ref = hlua_register_metatable(L, CLASS_SERVER);

	/* Create proxy object. */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "pause", hlua_proxy_pause);
	hlua_class_function(L, "resume", hlua_proxy_resume);
	hlua_class_function(L, "stop", hlua_proxy_stop);
	hlua_class_function(L, "shut_bcksess", hlua_proxy_shut_bcksess);
	hlua_class_function(L, "get_cap", hlua_proxy_get_cap);
	hlua_class_function(L, "get_mode", hlua_proxy_get_mode);
	hlua_class_function(L, "get_stats", hlua_proxy_get_stats);
	lua_settable(L, -3); /* -> META["__index"] = TABLE */
	class_proxy_ref = hlua_register_metatable(L, CLASS_PROXY);

	return 5;
}
