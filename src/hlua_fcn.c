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

#include <types/cli.h>
#include <types/hlua.h>
#include <types/proxy.h>
#include <types/stats.h>

#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/stats.h>
#include <proto/stick_table.h>

/* Contains the class reference of the concat object. */
static int class_concat_ref;
static int class_proxy_ref;
static int class_server_ref;
static int class_listener_ref;
static int class_regex_ref;
static int class_stktable_ref;

#define MAX_STK_FILTER_LEN 4
#define STATS_LEN (MAX((int)ST_F_TOTAL_FIELDS, (int)INF_TOTAL_FIELDS))

static THREAD_LOCAL struct field stats[STATS_LEN];

int hlua_checkboolean(lua_State *L, int index)
{
	if (!lua_isboolean(L, index))
		luaL_argerror(L, index, "boolean expected");
	return lua_toboolean(L, index);
}

/* Helper to push unsigned integers to Lua stack, respecting Lua limitations  */
static int hlua_fcn_pushunsigned(lua_State *L, unsigned int val)
{
#if (LUA_MAXINTEGER == LLONG_MAX || ((LUA_MAXINTEGER == LONG_MAX) && (__WORDSIZE == 64)))
	lua_pushinteger(L, val);
#else
	if (val > INT_MAX)
		lua_pushnumber(L, (lua_Number)val);
	else
		lua_pushinteger(L, (int)val);
#endif
	return 1;
}

/* Helper to push unsigned long long to Lua stack, respecting Lua limitations  */
static int hlua_fcn_pushunsigned_ll(lua_State *L, unsigned long long val) {
#if (LUA_MAXINTEGER == LLONG_MAX || ((LUA_MAXINTEGER == LONG_MAX) && (__WORDSIZE == 64)))
	/* 64 bits case, U64 is supported until LLONG_MAX */
	if (val > LLONG_MAX)
		lua_pushnumber(L, (lua_Number)val);
	else
		lua_pushinteger(L, val);
#else
	/* 32 bits case, U64 is supported until INT_MAX */
	if (val > INT_MAX)
		lua_pushnumber(L, (lua_Number)val);
	else
		lua_pushinteger(L, (int)val);
#endif
	return 1;
}

/* This function gets a struct field and converts it in Lua
 * variable. The variable is pushed at the top of the stack.
 */
int hlua_fcn_pushfield(lua_State *L, struct field *field)
{
	/* The lua_Integer is always signed. Its length depends on
	 * compilation options, so the following code is conditioned
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

/* This function returns a string containing the HAProxy object name. */
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
	time = my_timegm(&tm);
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
		lua_pushstring(L, info_fields[i].name);
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

int hlua_fcn_new_stktable(lua_State *L, struct stktable *tbl)
{
	lua_newtable(L);

	/* Pop a class stktbl metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_stktable_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, tbl);
	lua_rawseti(L, -2, 0);
	return 1;
}

static struct stktable *hlua_check_stktable(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_stktable_ref);
}

/* Extract stick table attributes into Lua table */
int hlua_stktable_info(lua_State *L)
{
	struct stktable *tbl;
	int dt;

	tbl = hlua_check_stktable(L, 1);

	if (!tbl->id) {
		lua_pushnil(L);
		return 1;
	}

	lua_newtable(L);

	lua_pushstring(L, "type");
	lua_pushstring(L, stktable_types[tbl->type].kw);
	lua_settable(L, -3);

	lua_pushstring(L, "length");
	lua_pushinteger(L, tbl->key_size);
	lua_settable(L, -3);

	lua_pushstring(L, "size");
	hlua_fcn_pushunsigned(L, tbl->size);
	lua_settable(L, -3);

	lua_pushstring(L, "used");
	hlua_fcn_pushunsigned(L, tbl->current);
	lua_settable(L, -3);

	lua_pushstring(L, "nopurge");
	lua_pushboolean(L, tbl->nopurge > 0);
	lua_settable(L, -3);

	lua_pushstring(L, "expire");
	lua_pushinteger(L, tbl->expire);
	lua_settable(L, -3);

	/* Save data types periods (if applicable) in 'data' table */
	lua_pushstring(L, "data");
	lua_newtable(L);

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		if (tbl->data_ofs[dt] == 0)
			continue;

		lua_pushstring(L, stktable_data_types[dt].name);

		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			lua_pushinteger(L, tbl->data_arg[dt].u);
		else
			lua_pushinteger(L, -1);

		lua_settable(L, -3);
	}

	lua_settable(L, -3);

	return 1;
}

/* Helper to get extract stick table entry into Lua table */
static void hlua_stktable_entry(lua_State *L, struct stktable *t, struct stksess *ts)
{
	int dt;
	void *ptr;

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {

		if (t->data_ofs[dt] == 0)
			continue;

		lua_pushstring(L, stktable_data_types[dt].name);

		ptr = stktable_data_ptr(t, ts, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			lua_pushinteger(L, stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			hlua_fcn_pushunsigned(L, stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			hlua_fcn_pushunsigned_ll(L, stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			lua_pushinteger(L, read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
			                t->data_arg[dt].u));
			break;
		}

		lua_settable(L, -3);
	}
}

/* Looks in table <t> for a sticky session matching key <key>
 * Returns table with session data or nil
 *
 * The returned table always contains 'use' and 'expire' (integer) fields.
 * For frequency/rate counters, each data entry is returned as table with
 * 'value' and 'period' fields.
 */
int hlua_stktable_lookup(lua_State *L)
{
	struct stktable *t;
	struct sample smp;
	struct stktable_key *skey;
	struct stksess *ts;

	t = hlua_check_stktable(L, 1);
	smp.data.type = SMP_T_STR;
	smp.flags = SMP_F_CONST;
	smp.data.u.str.area = (char *)luaL_checkstring(L, 2);

	skey = smp_to_stkey(&smp, t);
	if (!skey) {
		lua_pushnil(L);
		return 1;
	}

	ts = stktable_lookup_key(t, skey);
	if (!ts) {
		lua_pushnil(L);
		return 1;
	}

	lua_newtable(L);
	lua_pushstring(L, "use");
	lua_pushinteger(L, ts->ref_cnt - 1);
	lua_settable(L, -3);

	lua_pushstring(L, "expire");
	lua_pushinteger(L, tick_remain(now_ms, ts->expire));
	lua_settable(L, -3);

	hlua_stktable_entry(L, t, ts);
	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	ts->ref_cnt--;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return 1;
}

struct stk_filter {
	long long val;
	int type;
	int op;
};


/* Helper for returning errors to callers using Lua convention (nil, err) */
static int hlua_error(lua_State *L, const char *fmt, ...)  {
	char buf[256];
	int len;
	va_list args;
	va_start(args, fmt);
        len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len < 0) {
		ha_alert("hlua_error(): Could not write error message.\n");
		lua_pushnil(L);
		return 1;
	} else if (len >= sizeof(buf))
		ha_alert("hlua_error(): Error message was truncated.\n");

	lua_pushnil(L);
	lua_pushstring(L, buf);

	return 2;
}

/* Dump the contents of stick table <t>*/
int hlua_stktable_dump(lua_State *L)
{
	struct stktable *t;
	struct ebmb_node *eb;
	struct ebmb_node *n;
	struct stksess *ts;
	int type;
	int op;
	int dt;
	long long val;
	struct stk_filter filter[MAX_STK_FILTER_LEN];
	int filter_count = 0;
	int i;
	int skip_entry;
	void *ptr;

	t = hlua_check_stktable(L, 1);
	type = lua_type(L, 2);

	switch (type) {
	case LUA_TNONE:
	case LUA_TNIL:
		break;
	case LUA_TTABLE:
		lua_pushnil(L);
		while (lua_next(L, 2) != 0) {
			int entry_idx = 0;

			if (filter_count >= MAX_STK_FILTER_LEN)
				return hlua_error(L, "Filter table too large (len > %d)", MAX_STK_FILTER_LEN);

			if (lua_type(L, -1) != LUA_TTABLE  || lua_rawlen(L, -1) != 3)
				return hlua_error(L, "Filter table entry must be a triplet: {\"data_col\", \"op\", val} (entry #%d)", filter_count + 1);

			lua_pushnil(L);
			while (lua_next(L, -2) != 0) {
				switch (entry_idx) {
				case 0:
					if (lua_type(L, -1) != LUA_TSTRING)
						return hlua_error(L, "Filter table data column must be string (entry #%d)", filter_count + 1);

					dt = stktable_get_data_type((char *)lua_tostring(L, -1));
					if (dt < 0 || t->data_ofs[dt] == 0)
						return hlua_error(L, "Filter table data column not present in stick table (entry #%d)", filter_count + 1);
					filter[filter_count].type = dt;
					break;
				case 1:
					if (lua_type(L, -1) != LUA_TSTRING)
						return hlua_error(L, "Filter table operator must be string (entry #%d)", filter_count + 1);

					op = get_std_op(lua_tostring(L, -1));
					if (op < 0)
						return hlua_error(L, "Unknown operator in filter table (entry #%d)", filter_count + 1);
					filter[filter_count].op = op;
					break;
				case 2:
					val = lua_tointeger(L, -1);
					filter[filter_count].val = val;
					filter_count++;
					break;
				default:
					break;
				}
				entry_idx++;
				lua_pop(L, 1);
			}
			lua_pop(L, 1);
		}
		break;
	default:
		return hlua_error(L, "filter table expected");
	}

	lua_newtable(L);

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	eb = ebmb_first(&t->keys);
	for (n = eb; n; n = ebmb_next(n)) {
		ts = ebmb_entry(n, struct stksess, key);
		if (!ts) {
			HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
			return 1;
		}
		ts->ref_cnt++;
		HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

		/* multi condition/value filter */
		skip_entry = 0;
		for (i = 0; i < filter_count; i++) {
			if (t->data_ofs[filter[i].type] == 0)
				continue;

			ptr = stktable_data_ptr(t, ts, filter[i].type);

			switch (stktable_data_types[filter[i].type].std_type) {
			case STD_T_SINT:
				val = stktable_data_cast(ptr, std_t_sint);
				break;
			case STD_T_UINT:
				val = stktable_data_cast(ptr, std_t_uint);
				break;
			case STD_T_ULL:
				val = stktable_data_cast(ptr, std_t_ull);
				break;
			case STD_T_FRQP:
				val = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
						           t->data_arg[filter[i].type].u);
				break;
			default:
				continue;
				break;
			}

			op = filter[i].op;

			if ((val < filter[i].val && (op == STD_OP_EQ || op == STD_OP_GT || op == STD_OP_GE)) ||
			    (val == filter[i].val && (op == STD_OP_NE || op == STD_OP_GT || op == STD_OP_LT)) ||
			    (val > filter[i].val && (op == STD_OP_EQ || op == STD_OP_LT || op == STD_OP_LE))) {
				skip_entry = 1;
				break;
			}
		}

		if (skip_entry) {
			HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
			ts->ref_cnt--;
			continue;
		}

		if (t->type == SMP_T_IPV4) {
			char addr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, (const void *)&ts->key.key, addr, sizeof(addr));
			lua_pushstring(L, addr);
		} else if (t->type == SMP_T_IPV6) {
			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, (const void *)&ts->key.key, addr, sizeof(addr));
			lua_pushstring(L, addr);
		} else if (t->type == SMP_T_SINT) {
			lua_pushinteger(L, *ts->key.key);
		} else if (t->type == SMP_T_STR) {
			lua_pushstring(L, (const char *)ts->key.key);
		} else {
			return hlua_error(L, "Unsupported stick table key type");
		}

		lua_newtable(L);
		hlua_stktable_entry(L, t, ts);
		lua_settable(L, -3);
		HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
		ts->ref_cnt--;
	}
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

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

	if (!li->bind_conf->frontend) {
		lua_pushnil(L);
		return 1;
	}

	stats_fill_li_stats(li->bind_conf->frontend, li, STAT_SHLGNDS, stats, STATS_LEN);

	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_fields[i].name);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;

}

int hlua_fcn_new_server(lua_State *L, struct server *srv)
{
	char buffer[12];

	lua_newtable(L);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_server_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, srv);
	lua_rawseti(L, -2, 0);

	/* Add server name. */
	lua_pushstring(L, "name");
	lua_pushstring(L, srv->id);
	lua_settable(L, -3);

	/* Add server puid. */
	lua_pushstring(L, "puid");
	snprintf(buffer, sizeof(buffer), "%d", srv->puid);
	lua_pushstring(L, buffer);
	lua_settable(L, -3);

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

	stats_fill_sv_stats(srv->proxy, srv, STAT_SHLGNDS, stats, STATS_LEN);

	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_fields[i].name);
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
		snprintf(addr, INET_ADDRSTRLEN, "%d", srv->svc_port);
		luaL_addstring(&b, addr);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&srv->addr)->sin6_addr,
		          addr, INET6_ADDRSTRLEN);
		luaL_addstring(&b, addr);
		luaL_addstring(&b, ":");
		snprintf(addr, INET_ADDRSTRLEN, "%d", srv->svc_port);
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

int hlua_server_set_maxconn(lua_State *L)
{
	struct server *srv;
	const char *maxconn;
	const char *err;

	srv = hlua_check_server(L, 1);
	maxconn = luaL_checkstring(L, 2);

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	err = server_parse_maxconn_change_request(srv, maxconn);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	if (!err)
		lua_pushnil(L);
	else
		hlua_pushstrippedstring(L, err);
	return 1;
}

int hlua_server_get_maxconn(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	lua_pushinteger(L, srv->maxconn);
	return 1;
}

int hlua_server_set_weight(lua_State *L)
{
	struct server *srv;
	const char *weight;
	const char *err;

	srv = hlua_check_server(L, 1);
	weight = luaL_checkstring(L, 2);

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	err = server_parse_weight_change_request(srv, weight);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
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

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	err = server_parse_addr_change_request(srv, addr, "Lua script");
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
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
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_shutdown_streams(srv, SF_ERR_KILLED);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_drain(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_drain(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_maint(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_maint(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_ready(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_ready(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_check_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->check.state & CHK_ST_CONFIGURED) {
		sv->check.state |= CHK_ST_ENABLED;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_disable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->check.state & CHK_ST_CONFIGURED) {
		sv->check.state &= ~CHK_ST_ENABLED;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_force_up(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_running(sv, "changed from Lua script", NULL);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_force_nolb(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_stopping(sv, "changed from Lua script", NULL);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = 0;
		srv_set_stopped(sv, "changed from Lua script", NULL);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_CONFIGURED) {
		sv->agent.state |= CHK_ST_ENABLED;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_disable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_CONFIGURED) {
		sv->agent.state &= ~CHK_ST_ENABLED;
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_force_up(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = sv->agent.rise + sv->agent.fall - 1;
		srv_set_running(sv, "changed from Lua script", NULL);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = 0;
		srv_set_stopped(sv, "changed from Lua script", NULL);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_fcn_new_proxy(lua_State *L, struct proxy *px)
{
	struct server *srv;
	struct listener *lst;
	int lid;
	char buffer[17];

	lua_newtable(L);

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_proxy_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, px);
	lua_rawseti(L, -2, 0);

	/* Add proxy name. */
	lua_pushstring(L, "name");
	lua_pushstring(L, px->id);
	lua_settable(L, -3);

	/* Add proxy uuid. */
	lua_pushstring(L, "uuid");
	snprintf(buffer, sizeof(buffer), "%d", px->uuid);
	lua_pushstring(L, buffer);
	lua_settable(L, -3);

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
			snprintf(buffer, sizeof(buffer), "sock-%d", lid);
			lid++;
			lua_pushstring(L, buffer);
		}
		hlua_fcn_new_listener(L, lst);
		lua_settable(L, -3);
	}
	lua_settable(L, -3);

	if (px->table && px->table->id) {
		lua_pushstring(L, "stktable");
		hlua_fcn_new_stktable(L, px->table);
		lua_settable(L, -3);
	}

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
		stats_fill_be_stats(px, STAT_SHLGNDS, stats, STATS_LEN);
	else
		stats_fill_fe_stats(px, stats, STATS_LEN);
	lua_newtable(L);
	for (i=0; i<ST_F_TOTAL_FIELDS; i++) {
		lua_pushstring(L, stat_fields[i].name);
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
	for (px = proxies_list; px; px = px->next) {
		lua_pushstring(L, px->id);
		hlua_fcn_new_proxy(L, px);
		lua_settable(L, -3);
	}

	/* push "proxies" in "core" */
	lua_settable(L, -3);

	/* Create proxies entry. */
	lua_pushstring(L, "frontends");
	lua_newtable(L);

	/* List all proxies. */
	for (px = proxies_list; px; px = px->next) {
		if (!(px->cap & PR_CAP_FE))
			continue;
		lua_pushstring(L, px->id);
		hlua_fcn_new_proxy(L, px);
		lua_settable(L, -3);
	}

	/* push "frontends" in "core" */
	lua_settable(L, -3);

	/* Create proxies entry. */
	lua_pushstring(L, "backends");
	lua_newtable(L);

	/* List all proxies. */
	for (px = proxies_list; px; px = px->next) {
		if (!(px->cap & PR_CAP_BE))
			continue;
		lua_pushstring(L, px->id);
		hlua_fcn_new_proxy(L, px);
		lua_settable(L, -3);
	}

	/* push "backend" in "core" */
	lua_settable(L, -3);

	return 1;
}

/* This Lua function take a string, a list of separators.
 * It tokenize the input string using the list of separators
 * as separator.
 *
 * The functionreturns a tablle filled with tokens.
 */
int hlua_tokenize(lua_State *L)
{
	const char *str;
	const char *sep;
	int index;
	const char *token;
	const char *p;
	const char *c;
	int ignore_empty;

	ignore_empty = 0;

	str = luaL_checkstring(L, 1);
	sep = luaL_checkstring(L, 2);
	if (lua_gettop(L) == 3)
		ignore_empty = hlua_checkboolean(L, 3);

	lua_newtable(L);
	index = 1;
	token = str;
	p = str;
	while(1) {
		for (c = sep; *c != '\0'; c++)
			if (*p == *c)
				break;
		if (*p == *c) {
			if ((!ignore_empty) || (p - token > 0)) {
				lua_pushlstring(L, token, p - token);
				lua_rawseti(L, -2, index);
				index++;
			}
			token = p + 1;
		}
		if (*p == '\0')
			break;
		p++;
	}

	return 1;
}

int hlua_parse_addr(lua_State *L)
{
	struct hlua_addr *addr;
	const char *str = luaL_checkstring(L, 1);
	unsigned char mask;

	addr = lua_newuserdata(L, sizeof(struct hlua_addr));
	if (!addr) {
		lua_pushnil(L);
		return 1;
	}

	if (str2net(str, PAT_MF_NO_DNS, &addr->addr.v4.ip, &addr->addr.v4.mask)) {
		addr->type = AF_INET;
		return 1;
	}

	if (str62net(str, &addr->addr.v6.ip, &mask)) {
		len2mask6(mask, &addr->addr.v6.mask);
		addr->type = AF_INET6;
		return 1;
	}

	lua_pop(L, 1);
	lua_pushnil(L);
	return 1;
}

int hlua_match_addr(lua_State *L)
{
	struct hlua_addr *addr1;
	struct hlua_addr *addr2;

	if (!lua_isuserdata(L, 1) ||
	    !lua_isuserdata(L, 2)) {
		lua_pushboolean(L, 0);
		return 1;
	}

	addr1 = lua_touserdata(L, 1);
	addr2 = lua_touserdata(L, 2);

	if (addr1->type != addr2->type) {
		lua_pushboolean(L, 0);
		return 1;
	}

	if (addr1->type == AF_INET) {
		if ((addr1->addr.v4.ip.s_addr & addr2->addr.v4.mask.s_addr) ==
		    (addr2->addr.v4.ip.s_addr & addr1->addr.v4.mask.s_addr)) {
			lua_pushboolean(L, 1);
			return 1;
		}
	} else {
		int i;

		for (i = 0; i < 16; i += 4) {
			if ((*(uint32_t *)&addr1->addr.v6.ip.s6_addr[i] &
			     *(uint32_t *)&addr2->addr.v6.mask.s6_addr[i]) !=
			    (*(uint32_t *)&addr2->addr.v6.ip.s6_addr[i] &
			     *(uint32_t *)&addr1->addr.v6.mask.s6_addr[i]))
				break;
		}
		if (i == 16) {
			lua_pushboolean(L, 1);
			return 1;
		}
	}

	lua_pushboolean(L, 0);
	return 1;
}

static struct my_regex **hlua_check_regex(lua_State *L, int ud)
{
	return (hlua_checkudata(L, ud, class_regex_ref));
}

static int hlua_regex_comp(struct lua_State *L)
{
	struct my_regex **regex;
	const char *str;
	int cs;
	char *err;

	str = luaL_checkstring(L, 1);
	luaL_argcheck(L, lua_isboolean(L, 2), 2, NULL);
	cs = lua_toboolean(L, 2);

	regex = lua_newuserdata(L, sizeof(*regex));

	err = NULL;
	if (!(*regex = regex_comp(str, cs, 1, &err))) {
		lua_pushboolean(L, 0); /* status error */
		lua_pushstring(L, err); /* Reason */
		free(err);
		return 2;
	}

	lua_pushboolean(L, 1); /* Status ok */

	/* Create object */
	lua_newtable(L);
	lua_pushvalue(L, -3); /* Get the userdata pointer. */
	lua_rawseti(L, -2, 0);
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_regex_ref);
	lua_setmetatable(L, -2);
	return 2;
}

static int hlua_regex_exec(struct lua_State *L)
{
	struct my_regex **regex;
	const char *str;
	size_t len;
	struct buffer *tmp;

	regex = hlua_check_regex(L, 1);
	str = luaL_checklstring(L, 2, &len);

	if (!*regex) {
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Copy the string because regex_exec2 require a 'char *'
	 * and not a 'const char *'.
	 */
	tmp = get_trash_chunk();
	if (len >= tmp->size) {
		lua_pushboolean(L, 0);
		return 1;
	}
	memcpy(tmp->area, str, len);

	lua_pushboolean(L, regex_exec2(*regex, tmp->area, len));

	return 1;
}

static int hlua_regex_match(struct lua_State *L)
{
	struct my_regex **regex;
	const char *str;
	size_t len;
	regmatch_t pmatch[20];
	int ret;
	int i;
	struct buffer *tmp;

	regex = hlua_check_regex(L, 1);
	str = luaL_checklstring(L, 2, &len);

	if (!*regex) {
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Copy the string because regex_exec2 require a 'char *'
	 * and not a 'const char *'.
	 */
	tmp = get_trash_chunk();
	if (len >= tmp->size) {
		lua_pushboolean(L, 0);
		return 1;
	}
	memcpy(tmp->area, str, len);

	ret = regex_exec_match2(*regex, tmp->area, len, 20, pmatch, 0);
	lua_pushboolean(L, ret);
	lua_newtable(L);
	if (ret) {
		for (i = 0; i < 20 && pmatch[i].rm_so != -1; i++) {
			lua_pushlstring(L, str + pmatch[i].rm_so, pmatch[i].rm_eo - pmatch[i].rm_so);
			lua_rawseti(L, -2, i + 1);
		}
	}
	return 2;
}

static int hlua_regex_free(struct lua_State *L)
{
	struct my_regex **regex;

	regex = hlua_check_regex(L, 1);
	regex_free(*regex);
	*regex = NULL;
	return 0;
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
	hlua_class_function(L, "parse_addr", hlua_parse_addr);
	hlua_class_function(L, "match_addr", hlua_match_addr);
	hlua_class_function(L, "tokenize", hlua_tokenize);

	/* Create regex object. */
	lua_newtable(L);
	hlua_class_function(L, "new", hlua_regex_comp);

	lua_newtable(L); /* The metatable. */
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "exec", hlua_regex_exec);
	hlua_class_function(L, "match", hlua_regex_match);
	lua_rawset(L, -3); /* -> META["__index"] = TABLE */
	hlua_class_function(L, "__gc", hlua_regex_free);

	lua_pushvalue(L, -1); /* Duplicate the metatable reference. */
	class_regex_ref = hlua_register_metatable(L, CLASS_REGEX);

	lua_setmetatable(L, -2);
	lua_setglobal(L, CLASS_REGEX); /* Create global object called Regex */

	/* Create stktable object. */
	lua_newtable(L);
	lua_pushstring(L, "__index");
	lua_newtable(L);
	hlua_class_function(L, "info", hlua_stktable_info);
	hlua_class_function(L, "lookup", hlua_stktable_lookup);
	hlua_class_function(L, "dump", hlua_stktable_dump);
	lua_settable(L, -3); /* -> META["__index"] = TABLE */
	class_stktable_ref = hlua_register_metatable(L, CLASS_STKTABLE);

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
	hlua_class_function(L, "set_maxconn", hlua_server_set_maxconn);
	hlua_class_function(L, "get_maxconn", hlua_server_get_maxconn);
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
