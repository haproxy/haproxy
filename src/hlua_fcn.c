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

#define _GNU_SOURCE

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <import/ebmbtree.h>

#include <haproxy/cli-t.h>
#include <haproxy/errors.h>
#include <haproxy/hlua.h>
#include <haproxy/hlua_fcn.h>
#include <haproxy/http.h>
#include <haproxy/net_helper.h>
#include <haproxy/pattern.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/regex.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/stick_table.h>
#include <haproxy/event_hdl.h>
#include <haproxy/stream-t.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/mailers.h>

/* Contains the class reference of the concat object. */
static int class_concat_ref;
static int class_queue_ref;
static int class_proxy_ref;
static int class_server_ref;
static int class_listener_ref;
static int class_event_sub_ref;
static int class_patref_ref;
static int class_regex_ref;
static int class_stktable_ref;
static int class_proxy_list_ref;
static int class_server_list_ref;

#define STATS_LEN (MAX((int)ST_I_PX_MAX, (int)ST_I_INF_MAX))

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
		/* 64 bits case, S64 is supported between INT_MIN and INT_MAX */
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
	int l;

	for (p = str; HTTP_IS_LWS(*p); p++);

	for (l = strlen(p); l && HTTP_IS_LWS(p[l-1]); l--);

	return lua_pushlstring(L, p, l);
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
 * The original table is popped from the top of the stack.
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
	 * reference is copied first because the function
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
	/* WT: the doc says "returns the current time" and later says that it's
	 * monotonic. So the best fit is to use start_date+(now-start_time).
	 */
	struct timeval tv;

	tv = NS_TO_TV(now_ns - start_time_ns);
	tv_add(&tv, &tv, &start_date);

	lua_newtable(L);
	lua_pushstring(L, "sec");
	lua_pushinteger(L, tv.tv_sec);
	lua_rawset(L, -3);
	lua_pushstring(L, "usec");
	lua_pushinteger(L, tv.tv_usec);
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

	stats_fill_info(stats, STATS_LEN, 0);

	lua_newtable(L);
	for (i=0; i<ST_I_INF_MAX; i++) {
		lua_pushstring(L, stat_cols_info[i].name);
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

	/* Push the soncatenated string in the stack. */
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

static void hlua_concat_init(lua_State *L)
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
}

/* C backing storage for lua Queue class */
struct hlua_queue {
	uint32_t size;
	struct mt_list list;
	struct mt_list wait_tasks;
};

/* used to store lua objects in queue->list */
struct hlua_queue_item {
	int ref; /* lua object reference id */
	struct mt_list list;
};

/* used to store wait entries in queue->wait_tasks */
struct hlua_queue_wait
{
	struct task *task;
	struct mt_list entry;
};

/* This is the memory pool containing struct hlua_queue_item (queue items)
 */
DECLARE_STATIC_POOL(pool_head_hlua_queue, "hlua_queue", sizeof(struct hlua_queue_item));

/* This is the memory pool containing struct hlua_queue_wait
 * (queue waiting tasks)
 */
DECLARE_STATIC_POOL(pool_head_hlua_queuew, "hlua_queuew", sizeof(struct hlua_queue_wait));

static struct hlua_queue *hlua_check_queue(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_queue_ref);
}

/* queue:size(): returns an integer containing the current number of queued
 * items.
 */
static int hlua_queue_size(lua_State *L)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);

	BUG_ON(!queue);
	lua_pushinteger(L, HA_ATOMIC_LOAD(&queue->size));

	return 1;
}

/* queue:push(): push an item (any type, except nil) at the end of the queue
 *
 * Returns boolean:true for success and boolean:false on error
 */
static int hlua_queue_push(lua_State *L)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);
	struct hlua_queue_item *item;
	struct mt_list back;
	struct hlua_queue_wait *waiter;

	if (lua_gettop(L) != 2 || lua_isnoneornil(L, 2)) {
		luaL_error(L, "unexpected argument");
		/* not reached */
		return 0;
	}
	BUG_ON(!queue);

	item = pool_alloc(pool_head_hlua_queue);
	if (!item) {
		/* memory error */
		lua_pushboolean(L, 0);
		return 1;
	}

	/* get a reference from lua object at the top of the stack */
	item->ref = hlua_ref(L);

	/* push new entry to the queue */
	MT_LIST_INIT(&item->list);
	HA_ATOMIC_INC(&queue->size);
	MT_LIST_APPEND(&queue->list, &item->list);

	/* notify tasks waiting on queue:pop_wait() (if any) */
	MT_LIST_FOR_EACH_ENTRY_LOCKED(waiter, &queue->wait_tasks, entry, back) {
		task_wakeup(waiter->task, TASK_WOKEN_MSG);
	}

	lua_pushboolean(L, 1);
	return 1;
}

/* internal queue pop helper, returns 1 if it successfully popped an item
 * from the queue and pushed it on lua stack.
 *
 * Else it returns 0 (nothing is pushed on the stack)
 */
static int _hlua_queue_pop(lua_State *L, struct hlua_queue *queue)
{
	struct hlua_queue_item *item;

	item = MT_LIST_POP(&queue->list, typeof(item), list);
	if (!item)
		return 0; /* nothing in queue */

	HA_ATOMIC_DEC(&queue->size);
	/* push lua obj on the stack */
	hlua_pushref(L, item->ref);

	/* obj ref should be released right away since it was pushed
	 * on the stack and will not be used anymore
	 */
	hlua_unref(L, item->ref);

	/* free the queue item */
	pool_free(pool_head_hlua_queue, item);

	return 1;
}

/* queue:pop(): returns the first item at the top of que queue or nil if
 * the queue is empty.
 */
static int hlua_queue_pop(lua_State *L)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);

	BUG_ON(!queue);
	if (!_hlua_queue_pop(L, queue)) {
		/* nothing in queue, push nil */
		lua_pushnil(L);
	}
	return 1; /* either item or nil is at the top of the stack */
}

/* queue:pop_wait(): same as queue:pop() but doesn't return on empty queue.
 *
 * Aborts if used incorrectly and returns nil in case of memory error.
 */
static int _hlua_queue_pop_wait(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);
	struct hlua_queue_wait *wait = lua_touserdata(L, 2);

	/* new pop attempt */
	if (!_hlua_queue_pop(L, queue)) {
		hlua_yieldk(L, 0, 0, _hlua_queue_pop_wait, TICK_ETERNITY, 0); // wait retry
		return 0; // never reached, yieldk won't return
	}

	/* remove task from waiting list */
	MT_LIST_DELETE(&wait->entry);
	pool_free(pool_head_hlua_queuew, wait);

	return 1; // success
}
static int hlua_queue_pop_wait(lua_State *L)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);
	struct hlua_queue_wait *wait;
	struct hlua *hlua;

	BUG_ON(!queue);

	/* Get hlua struct, or NULL if we execute from main lua state */
	hlua = hlua_gethlua(L);

	if (!hlua || HLUA_CANT_YIELD(hlua)) {
		luaL_error(L, "pop_wait() may only be used within task context "
			      "(requires yielding)");
		return 0; /* not reached */
	}

	/* try opportunistic pop (there could already be pending items) */
	if (_hlua_queue_pop(L, queue))
		return 1; // success

	/* no pending items, waiting required */

	wait = pool_alloc(pool_head_hlua_queuew);
	if (!wait) {
		lua_pushnil(L);
		return 1; /* memory error, return nil */
	}

	wait->task = hlua->task;
	MT_LIST_INIT(&wait->entry);

	/* add task to queue's wait list */
	MT_LIST_TRY_APPEND(&queue->wait_tasks, &wait->entry);

	/* push wait entry at index 2 on the stack (queue is already there) */
	lua_pushlightuserdata(L, wait);

	/* Go to waiting loop which immediately performs a new attempt to make
	 * sure we didn't miss a push during the wait entry initialization.
	 *
	 * _hlua_queue_pop_wait() won't return to us if it has to yield, which
	 * is the most likely scenario. What happens in this case is that yieldk
	 * call never returns, and instead Lua will call the continuation
	 * function after a successful resume, so the calling function will
	 * no longer be us, but Lua instead. And when the continuation function
	 * eventually returns (because it successfully popped an item), Lua will
	 * directly give the hand back to the Lua function that called us.
	 *
	 * More info here: https://www.lua.org/manual/5.4/manual.html#4.7
	 */
	return _hlua_queue_pop_wait(L, LUA_OK, 0);
}

static int hlua_queue_new(lua_State *L)
{
	struct hlua_queue *q;

	lua_newtable(L);

	/* set class metatable */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_queue_ref);
	lua_setmetatable(L, -2);

	/* index:0 is queue userdata (c data) */
	q = lua_newuserdata(L, sizeof(*q));
	MT_LIST_INIT(&q->list);
	MT_LIST_INIT(&q->wait_tasks);
	q->size = 0;
	lua_rawseti(L, -2, 0);

	/* class methods */
	hlua_class_function(L, "size", hlua_queue_size);
	hlua_class_function(L, "pop", hlua_queue_pop);
	hlua_class_function(L, "pop_wait", hlua_queue_pop_wait);
	hlua_class_function(L, "push", hlua_queue_push);

	return 1;
}

static int hlua_queue_gc(struct lua_State *L)
{
	struct hlua_queue *queue = hlua_check_queue(L, 1);
	struct hlua_queue_wait *wait;
	struct hlua_queue_item *item;

	/* Purge waiting tasks (if any)
	 *
	 * It is normally not expected to have waiting tasks, except if such
	 * task has been aborted while in the middle of a queue:pop_wait()
	 * function call.
	 */
	while ((wait = MT_LIST_POP(&queue->wait_tasks, typeof(wait), entry))) {
		/* free the wait entry */
		pool_free(pool_head_hlua_queuew, wait);
	}

	/* purge remaining (unconsumed) items in the queue */
	while ((item = MT_LIST_POP(&queue->list, typeof(item), list))) {
		/* free the queue item */
		pool_free(pool_head_hlua_queue, item);
	}

	/* queue (userdata) will automatically be freed by lua gc */

	return 0;
}

static void hlua_queue_init(lua_State *L)
{
	/* Creates the queue object. */
	lua_newtable(L);

	hlua_class_function(L, "__gc", hlua_queue_gc);

	class_queue_ref = luaL_ref(L, LUA_REGISTRYINDEX);
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
	lua_pushboolean(L, (tbl->flags & STK_FL_NOPURGE));
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

		ptr = stktable_data_ptr(t, ts, dt);
		if (!ptr)
			continue;

		lua_pushstring(L, stktable_data_types[dt].name);

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
		case STD_T_DICT: {
			struct dict_entry *de;
			de = stktable_data_cast(ptr, std_t_dict);
			lua_pushstring(L, de ? (char *)de->value.key : "-");
			break;
		}
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
	smp.data.u.str.area = (char *)lua_tolstring(L, 2, &smp.data.u.str.data);

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
	lua_pushinteger(L, HA_ATOMIC_LOAD(&ts->ref_cnt) - 1);
	lua_settable(L, -3);

	lua_pushstring(L, "expire");
	lua_pushinteger(L, tick_remain(now_ms, ts->expire));
	lua_settable(L, -3);

	hlua_stktable_entry(L, t, ts);
	HA_ATOMIC_DEC(&ts->ref_cnt);

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
	struct stk_filter filter[STKTABLE_FILTER_LEN];
	int filter_count = 0;
	int i;
	int skip_entry;
	void *ptr;
	int shard = 0; // FIXME: this should be stored in the context and iterate to scan the table

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

			if (filter_count >= STKTABLE_FILTER_LEN)
				return hlua_error(L, "Filter table too large (len > %d)", STKTABLE_FILTER_LEN);

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

 next_shard:
	HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	eb = ebmb_first(&t->shards[shard].keys);
	for (n = eb; n; n = ebmb_next(n)) {
		ts = ebmb_entry(n, struct stksess, key);
		if (!ts) {
			HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
			goto done;
		}
		HA_ATOMIC_INC(&ts->ref_cnt);
		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

		/* multi condition/value filter */
		skip_entry = 0;
		for (i = 0; i < filter_count; i++) {
			ptr = stktable_data_ptr(t, ts, filter[i].type);
			if (!ptr)
				continue;

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
			HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
			HA_ATOMIC_DEC(&ts->ref_cnt);
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
		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
		HA_ATOMIC_DEC(&ts->ref_cnt);
	}
	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
 done:
	shard++;
	if (shard < CONFIG_HAP_TBL_BUCKETS)
		goto next_shard;

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

	stats_fill_li_line(li->bind_conf->frontend, li, STAT_F_SHLGNDS, stats,
	                   STATS_LEN, NULL);

	lua_newtable(L);
	for (i=0; i<ST_I_PX_MAX; i++) {
		lua_pushstring(L, stat_cols_px[i].name);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;

}

int hlua_server_gc(lua_State *L)
{
	struct server *srv = hlua_checkudata(L, 1, class_server_ref);

	srv_drop(srv); /* srv_drop allows NULL srv */
	return 0;
}

static struct server *hlua_check_server(lua_State *L, int ud)
{
	struct server *srv = hlua_checkudata(L, ud, class_server_ref);
	if (srv->flags & SRV_F_DELETED) {
		return NULL;
	}
	return srv;
}

int hlua_server_get_stats(lua_State *L)
{
	struct server *srv;
	int i;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	if (!srv->proxy) {
		lua_pushnil(L);
		return 1;
	}

	stats_fill_sv_line(srv->proxy, srv, STAT_F_SHLGNDS, stats,
	                   STATS_LEN, NULL);

	lua_newtable(L);
	for (i=0; i<ST_I_PX_MAX; i++) {
		lua_pushstring(L, stat_cols_px[i].name);
		hlua_fcn_pushfield(L, &stats[i]);
		lua_settable(L, -3);
	}
	return 1;

}

int hlua_server_get_proxy(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	if (!srv->proxy) {
		lua_pushnil(L);
		return 1;
	}

	hlua_fcn_new_proxy(L, srv->proxy);
	return 1;
}

int hlua_server_get_addr(lua_State *L)
{
	struct server *srv;
	char addr[INET6_ADDRSTRLEN];
	luaL_Buffer b;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);

	switch (real_family(srv->addr.ss_family)) {
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

int hlua_server_get_puid(lua_State *L)
{
	struct server *srv;
	char buffer[12];

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	snprintf(buffer, sizeof(buffer), "%d", srv->puid);
	lua_pushstring(L, buffer);
	return 1;
}

int hlua_server_get_rid(lua_State *L)
{
	struct server *srv;
	char buffer[12];

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	snprintf(buffer, sizeof(buffer), "%d", srv->rid);
	lua_pushstring(L, buffer);
	return 1;
}

int hlua_server_get_name(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, srv->id);
	return 1;
}

/* __index metamethod for server class
 * support for additional keys that are missing from the main table
 * stack:1 = table (server class), stack:2 = requested key
 * Returns 1 if key is supported
 * else returns 0 to make lua return NIL value to the caller
 */
static int hlua_server_index(struct lua_State *L)
{
	const char *key = lua_tostring(L, 2);

	if (strcmp(key, "name") == 0) {
		if (ONLY_ONCE())
			ha_warning("hlua: use of server 'name' attribute is deprecated and will eventually be removed, please use get_name() function instead: %s\n", hlua_traceback(L, ", "));
		lua_pushvalue(L, 1);
		hlua_server_get_name(L);
		return 1;
	}
	if (strcmp(key, "puid") == 0) {
		if (ONLY_ONCE())
			ha_warning("hlua: use of server 'puid' attribute is deprecated and will eventually be removed, please use get_puid() function instead: %s\n", hlua_traceback(L, ", "));
		lua_pushvalue(L, 1);
		hlua_server_get_puid(L);
		return 1;
	}
	/* unknown attribute */
	return 0;
}

int hlua_server_is_draining(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushboolean(L, server_is_draining(srv));
	return 1;
}

int hlua_server_is_backup(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushboolean(L, (srv->flags & SRV_F_BACKUP));
	return 1;
}

int hlua_server_is_dynamic(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushboolean(L, (srv->flags & SRV_F_DYNAMIC));
	return 1;
}

int hlua_server_get_cur_sess(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, srv->cur_sess);
	return 1;
}

int hlua_server_get_pend_conn(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, srv->queueslength);
	return 1;
}

int hlua_server_set_maxconn(lua_State *L)
{
	struct server *srv;
	const char *maxconn;
	const char *err;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

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
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, srv->maxconn);
	return 1;
}

int hlua_server_set_weight(lua_State *L)
{
	struct server *srv;
	const char *weight;
	const char *err;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

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
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, srv->uweight);
	return 1;
}

int hlua_server_set_addr(lua_State *L)
{
	struct server *srv;
	const char *addr;
	const char *port;
	const char *err;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	addr = luaL_checkstring(L, 2);
	if (lua_gettop(L) >= 3)
		port = luaL_checkstring(L, 3);
	else
		port = NULL;

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	err = srv_update_addr_port(srv, addr, port, SERVER_INETADDR_UPDATER_LUA);
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
	if (srv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_shutdown_streams(srv, SF_ERR_KILLED);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_drain(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_drain(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_maint(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_maint(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_set_ready(lua_State *L)
{
	struct server *srv;

	srv = hlua_check_server(L, 1);
	if (srv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srv_adm_set_ready(srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	return 0;
}

int hlua_server_check_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
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
	if (sv == NULL) {
		return 0;
	}
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
	if (sv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_running(sv, SRV_OP_STCHGC_LUA);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_force_nolb(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = sv->check.rise + sv->check.fall - 1;
		srv_set_stopping(sv, SRV_OP_STCHGC_LUA);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_check_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (!(sv->track)) {
		sv->check.health = 0;
		srv_set_stopped(sv, SRV_OP_STCHGC_LUA);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_enable(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
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
	if (sv == NULL) {
		return 0;
	}
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
	if (sv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = sv->agent.rise + sv->agent.fall - 1;
		srv_set_running(sv, SRV_OP_STCHGC_LUA);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

int hlua_server_agent_force_down(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
	HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
	if (sv->agent.state & CHK_ST_ENABLED) {
		sv->agent.health = 0;
		srv_set_stopped(sv, SRV_OP_STCHGC_LUA);
	}
	HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
	return 0;
}

/* returns the tracked server, if any */
int hlua_server_tracking(lua_State *L)
{
	struct server *sv;
	struct server *tracked;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}

	tracked = sv->track;
	if (tracked == NULL)
		lua_pushnil(L);
	else
		hlua_fcn_new_server(L, tracked);

	return 1;
}

/* returns an array of servers tracking the current server */
int hlua_server_get_trackers(lua_State *L)
{
	struct server *sv;
	struct server *cur_tracker;
	int index;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}

	lua_newtable(L);
	cur_tracker = sv->trackers;
	for (index = 1; cur_tracker; cur_tracker = cur_tracker->tracknext, index++) {
		if (!lua_checkstack(L, 5))
			luaL_error(L, "Lua out of memory error.");
		hlua_fcn_new_server(L, cur_tracker);
		/* array index starts at 1 in Lua */
		lua_rawseti(L, -2, index);
	}
	return 1;
}

/* hlua_event_sub wrapper for per-server subscription:
 *
 * hlua_event_sub() is called with sv->e_subs subscription list and
 * lua arguments are passed as-is (skipping the first argument which
 * is the server ctx)
 */
int hlua_server_event_sub(lua_State *L)
{
	struct server *sv;

	sv = hlua_check_server(L, 1);
	if (sv == NULL) {
		return 0;
	}
	/* remove first argument from the stack (server) */
	lua_remove(L, 1);

	/* try to subscribe within server's subscription list */
	return hlua_event_sub(L, &sv->e_subs);
}

int hlua_fcn_new_server(lua_State *L, struct server *srv)
{
	lua_newtable(L);

	/* Pop a class server metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_server_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, srv);
	lua_rawseti(L, -2, 0);

	/* userdata is affected: increment server refcount */
	srv_take(srv);

	/* set public methods */
	hlua_class_function(L, "get_name", hlua_server_get_name);
	hlua_class_function(L, "get_puid", hlua_server_get_puid);
	hlua_class_function(L, "get_rid", hlua_server_get_rid);
	hlua_class_function(L, "is_draining", hlua_server_is_draining);
	hlua_class_function(L, "is_backup", hlua_server_is_backup);
	hlua_class_function(L, "is_dynamic", hlua_server_is_dynamic);
	hlua_class_function(L, "get_cur_sess", hlua_server_get_cur_sess);
	hlua_class_function(L, "get_pend_conn", hlua_server_get_pend_conn);
	hlua_class_function(L, "set_maxconn", hlua_server_set_maxconn);
	hlua_class_function(L, "get_maxconn", hlua_server_get_maxconn);
	hlua_class_function(L, "set_weight", hlua_server_set_weight);
	hlua_class_function(L, "get_weight", hlua_server_get_weight);
	hlua_class_function(L, "set_addr", hlua_server_set_addr);
	hlua_class_function(L, "get_addr", hlua_server_get_addr);
	hlua_class_function(L, "get_stats", hlua_server_get_stats);
	hlua_class_function(L, "get_proxy", hlua_server_get_proxy);
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
	hlua_class_function(L, "tracking", hlua_server_tracking);
	hlua_class_function(L, "get_trackers", hlua_server_get_trackers);
	hlua_class_function(L, "event_sub", hlua_server_event_sub);

	return 1;
}

static struct hlua_server_list *hlua_check_server_list(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_server_list_ref);
}

/* does nothing and returns 0, only prevents insertions in the
 * table which represents the list of servers
 */
int hlua_listable_servers_newindex(lua_State *L) {
	return 0;
}

/* first arg is the table (struct hlua_server_list * in metadata)
 * second arg is the required index
 */
int hlua_listable_servers_index(lua_State *L)
{
	struct hlua_server_list *hlua_srv;
	const char *name;
	struct server *srv;

	hlua_srv = hlua_check_server_list(L, 1);
	name = luaL_checkstring(L, 2);

	/* Perform a server lookup in px list */
	srv = server_find_by_name(hlua_srv->px, name);
	if (srv == NULL) {
		lua_pushnil(L);
		return 1;
	}

	hlua_fcn_new_server(L, srv);
	return 1;
}

/* iterator must return key as string and value as server
 * object, if we reach end of list, it returns nil.
 * The context knows the last returned server. if the
 * context contains srv == NULL, we start enumeration.
 * Then, use 'srv->next' ptr to iterate through the list
 */
int hlua_listable_servers_pairs_iterator(lua_State *L)
{
	int context_index;
	struct hlua_server_list_iterator_context *ctx;
	struct server *cur;

	context_index = lua_upvalueindex(1);
	ctx = lua_touserdata(L, context_index);

	if (ctx->px) {
		/* First iteration, initialize list on the first server */
		cur = ctx->px->srv;
		watcher_attach(&ctx->srv_watch, cur);
		ctx->px = NULL;
	}
	else {
		/* next iteration */
		cur = ctx->next;
	}

	/* cur server is null, end of iteration */
	if (cur == NULL) {
		lua_pushnil(L);
		return 1;
	}

	/* compute next server */
	ctx->next = watcher_next(&ctx->srv_watch, cur->next);

	lua_pushstring(L, cur->id);
	hlua_fcn_new_server(L, cur);
	return 2;
}

/* init the iterator context, return iterator function
 * with context as closure. The only argument is a
 * server list object.
 */
int hlua_listable_servers_pairs(lua_State *L)
{
	struct hlua_server_list_iterator_context *ctx;
	struct hlua_server_list *hlua_srv_list;

	hlua_srv_list = hlua_check_server_list(L, 1);

	ctx = lua_newuserdata(L, sizeof(*ctx));
	ctx->px = hlua_srv_list->px;
	ctx->next = NULL;
	watcher_init(&ctx->srv_watch, &ctx->next, offsetof(struct server, watcher_list));

	lua_pushcclosure(L, hlua_listable_servers_pairs_iterator, 1);
	return 1;
}

void hlua_listable_servers(lua_State *L, struct proxy *px)
{
	struct hlua_server_list *list;

	lua_newtable(L);
	list = lua_newuserdata(L, sizeof(*list));
	list->px = px;
	lua_rawseti(L, -2, 0);
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_server_list_ref);
	lua_setmetatable(L, -2);
}

static struct proxy *hlua_check_proxy(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_proxy_ref);
}

int hlua_proxy_get_name(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	lua_pushstring(L, px->id);
	return 1;
}

int hlua_proxy_get_uuid(lua_State *L)
{
	struct proxy *px;
	char buffer[17];

	px = hlua_check_proxy(L, 1);
	snprintf(buffer, sizeof(buffer), "%d", px->uuid);
	lua_pushstring(L, buffer);
	return 1;
}

/* __index metamethod for proxy class
 * support for additional keys that are missing from the main table
 * stack:1 = table (proxy class), stack:2 = requested key
 * Returns 1 if key is supported
 * else returns 0 to make lua return NIL value to the caller
 */
static int hlua_proxy_index(struct lua_State *L)
{
	const char *key = lua_tostring(L, 2);

	if (strcmp(key, "name") == 0) {
		if (ONLY_ONCE())
			ha_warning("hlua: use of proxy 'name' attribute is deprecated and will eventually be removed, please use get_name() function instead: %s\n", hlua_traceback(L, ", "));
		lua_pushvalue(L, 1);
		hlua_proxy_get_name(L);
		return 1;
	}
	if (strcmp(key, "uuid") == 0) {
		if (ONLY_ONCE())
			ha_warning("hlua: use of proxy 'uuid' attribute is deprecated and will eventually be removed, please use get_uuid() function instead: %s\n", hlua_traceback(L, ", "));
		lua_pushvalue(L, 1);
		hlua_proxy_get_uuid(L);
		return 1;
	}
	/* unknown attribute */
	return 0;
}

int hlua_proxy_pause(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	/* safe to call without PROXY_LOCK - pause_proxy takes it */
	pause_proxy(px);
	return 0;
}

int hlua_proxy_resume(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	/* safe to call without PROXY_LOCK - resume_proxy takes it */
	resume_proxy(px);
	return 0;
}

int hlua_proxy_stop(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	/* safe to call without PROXY_LOCK - stop_proxy takes it */
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
		stats_fill_be_line(px, STAT_F_SHLGNDS, stats, STATS_LEN, NULL);
	else
		stats_fill_fe_line(px, 0, stats, STATS_LEN, NULL);
	lua_newtable(L);
	for (i=0; i<ST_I_PX_MAX; i++) {
		lua_pushstring(L, stat_cols_px[i].name);
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

int hlua_proxy_get_srv_act(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	lua_pushinteger(L, px->srv_act);
	return 1;
}

int hlua_proxy_get_srv_bck(lua_State *L)
{
	struct proxy *px;

	px = hlua_check_proxy(L, 1);
	lua_pushinteger(L, px->srv_bck);
	return 1;
}

/* Get mailers config info, used to implement email alert sending
 * according to mailers config from lua.
 */
int hlua_proxy_get_mailers(lua_State *L)
{
	struct proxy *px;
	int it;
	struct mailer *mailer;

	px = hlua_check_proxy(L, 1);

	if (!px->email_alert.mailers.m)
		return 0; /* email-alert mailers not found on proxy */

	lua_newtable(L);

	/* option log-health-checks */
	lua_pushstring(L, "track_server_health");
	lua_pushboolean(L, (px->options2 & PR_O2_LOGHCHKS));
	lua_settable(L, -3);

	/* email-alert level */
	lua_pushstring(L, "log_level");
	lua_pushinteger(L, px->email_alert.level);
	lua_settable(L, -3);

	/* email-alert mailers */
	lua_pushstring(L, "mailservers");
	lua_newtable(L);
	for (it = 0, mailer = px->email_alert.mailers.m->mailer_list;
	     it < px->email_alert.mailers.m->count; it++, mailer = mailer->next) {
		char *srv_address;

		lua_pushstring(L, mailer->id);

		/* For now, we depend on mailer->addr to restore mailer's address which
		 * was converted using str2sa_range() on startup.
		 *
		 * FIXME?:
		 * It could be a good idea to pass the raw address (unparsed) to allow fqdn
		 * to be resolved at runtime, unless we consider this as a pure legacy mode
		 * and mailers config support is going to be removed in the future?
		 */
		srv_address = sa2str(&mailer->addr, get_host_port(&mailer->addr), 0);
		if (srv_address) {
			lua_pushstring(L, srv_address);
			ha_free(&srv_address);
			lua_settable(L, -3);
		}
	}
	lua_settable(L, -3);

	/* mailers timeout (from mailers section) */
	lua_pushstring(L, "mailservers_timeout");
	lua_pushinteger(L, px->email_alert.mailers.m->timeout.mail);
	lua_settable(L, -3);

	/* email-alert myhostname */
	lua_pushstring(L, "smtp_hostname");
	lua_pushstring(L, px->email_alert.myhostname);
	lua_settable(L, -3);

	/* email-alert from */
	lua_pushstring(L, "smtp_from");
	lua_pushstring(L, px->email_alert.from);
	lua_settable(L, -3);

	/* email-alert to */
	lua_pushstring(L, "smtp_to");
	lua_pushstring(L, px->email_alert.to);
	lua_settable(L, -3);

	return 1;
}

int hlua_fcn_new_proxy(lua_State *L, struct proxy *px)
{
	struct listener *lst;
	int lid;
	char buffer[17];

	lua_newtable(L);

	/* Pop a class proxy metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_proxy_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, px);
	lua_rawseti(L, -2, 0);

	/* set public methods */
	hlua_class_function(L, "get_name", hlua_proxy_get_name);
	hlua_class_function(L, "get_uuid", hlua_proxy_get_uuid);
	hlua_class_function(L, "pause", hlua_proxy_pause);
	hlua_class_function(L, "resume", hlua_proxy_resume);
	hlua_class_function(L, "stop", hlua_proxy_stop);
	hlua_class_function(L, "shut_bcksess", hlua_proxy_shut_bcksess);
	hlua_class_function(L, "get_cap", hlua_proxy_get_cap);
	hlua_class_function(L, "get_mode", hlua_proxy_get_mode);
	hlua_class_function(L, "get_srv_act", hlua_proxy_get_srv_act);
	hlua_class_function(L, "get_srv_bck", hlua_proxy_get_srv_bck);
	hlua_class_function(L, "get_stats", hlua_proxy_get_stats);
	hlua_class_function(L, "get_mailers", hlua_proxy_get_mailers);

	/* Browse and register servers. */
	lua_pushstring(L, "servers");
	hlua_listable_servers(L, px);
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

static struct hlua_proxy_list *hlua_check_proxy_list(lua_State *L, int ud)
{
	return hlua_checkudata(L, ud, class_proxy_list_ref);
}

/* does nothing and returns 0, only prevents insertions in the
 * table which represent list of proxies
 */
int hlua_listable_proxies_newindex(lua_State *L) {
	return 0;
}

/* first arg is the table (struct hlua_proxy_list * in metadata)
 * second arg is the required index
 */
int hlua_listable_proxies_index(lua_State *L)
{
	struct hlua_proxy_list *hlua_px;
	const char *name;
	struct proxy *px;

	hlua_px = hlua_check_proxy_list(L, 1);
	name = luaL_checkstring(L, 2);

	px = NULL;
	if (hlua_px->capabilities & PR_CAP_FE) {
		px = proxy_find_by_name(name, PR_CAP_FE, 0);
	}
	if (!px && hlua_px->capabilities & PR_CAP_BE) {
		px = proxy_find_by_name(name, PR_CAP_BE, 0);
	}
	if (px == NULL) {
		lua_pushnil(L);
		return 1;
	}

	hlua_fcn_new_proxy(L, px);
	return 1;
}

static inline int hlua_listable_proxies_match(struct proxy *px, char cap) {
	return ((px->cap & cap) && !(px->cap & (PR_CAP_DEF | PR_CAP_INT)));
}

/* iterator must return key as string and value as proxy
 * object, if we reach end of list, it returns nil
 */
int hlua_listable_proxies_pairs_iterator(lua_State *L)
{
	int context_index;
	struct hlua_proxy_list_iterator_context *ctx;

	context_index = lua_upvalueindex(1);
	ctx = lua_touserdata(L, context_index);

	if (ctx->next == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, ctx->next->id);
	hlua_fcn_new_proxy(L, ctx->next);

	for (ctx->next = ctx->next->next;
	     ctx->next && !hlua_listable_proxies_match(ctx->next, ctx->capabilities);
	     ctx->next = ctx->next->next);

	return 2;
}

/* init the iterator context, return iterator function
 * with context as closure. The only argument is a
 * proxy object.
 */
int hlua_listable_proxies_pairs(lua_State *L)
{
	struct hlua_proxy_list_iterator_context *ctx;
	struct hlua_proxy_list *hlua_px;

	hlua_px = hlua_check_proxy_list(L, 1);

	ctx = lua_newuserdata(L, sizeof(*ctx));

	ctx->capabilities = hlua_px->capabilities;
	for (ctx->next = proxies_list;
	     ctx->next && !hlua_listable_proxies_match(ctx->next, ctx->capabilities);
	     ctx->next = ctx->next->next);
	lua_pushcclosure(L, hlua_listable_proxies_pairs_iterator, 1);
	return 1;
}

void hlua_listable_proxies(lua_State *L, char capabilities)
{
	struct hlua_proxy_list *list;

	lua_newtable(L);
	list = lua_newuserdata(L, sizeof(*list));
	list->capabilities = capabilities;
	lua_rawseti(L, -2, 0);
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_proxy_list_ref);
	lua_setmetatable(L, -2);
}

int hlua_event_sub_unsub(lua_State *L)
{
	struct event_hdl_sub *sub = hlua_checkudata(L, 1, class_event_sub_ref);

	BUG_ON(!sub);
	event_hdl_take(sub); /* keep a reference on sub until the item is GCed */
	event_hdl_unsubscribe(sub); /* will automatically call event_hdl_drop() */
	return 0;
}

int hlua_event_sub_gc(lua_State *L)
{
	struct event_hdl_sub *sub = hlua_checkudata(L, 1, class_event_sub_ref);

	BUG_ON(!sub);
	event_hdl_drop(sub); /* final drop of the reference */
	return 0;
}

int hlua_fcn_new_event_sub(lua_State *L, struct event_hdl_sub *sub)
{
	lua_newtable(L);

	/* Pop a class event_sub metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_event_sub_ref);
	lua_setmetatable(L, -2);

	lua_pushlightuserdata(L, sub);
	lua_rawseti(L, -2, 0);

	/* userdata is affected: increment sub refcount */
	event_hdl_take(sub);

	/* set public methods */
	hlua_class_function(L, "unsub", hlua_event_sub_unsub);

	return 1;
}

/* This Lua function take a string, a list of separators.
 * It tokenize the input string using the list of separators
 * as separator.
 *
 * The functionreturns a table filled with tokens.
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
	struct net_addr *addr;
	const char *str = luaL_checkstring(L, 1);
	unsigned char mask;

	addr = lua_newuserdata(L, sizeof(struct net_addr));
	if (!addr) {
		lua_pushnil(L);
		return 1;
	}

	if (str2net(str, PAT_MF_NO_DNS, &addr->addr.v4.ip, &addr->addr.v4.mask)) {
		addr->family = AF_INET;
		return 1;
	}

	if (str62net(str, &addr->addr.v6.ip, &mask)) {
		len2mask6(mask, &addr->addr.v6.mask);
		addr->family = AF_INET6;
		return 1;
	}

	lua_pop(L, 1);
	lua_pushnil(L);
	return 1;
}

int hlua_match_addr(lua_State *L)
{
	struct net_addr *addr1;
	struct net_addr *addr2;

	if (!lua_isuserdata(L, 1) ||
	    !lua_isuserdata(L, 2)) {
		lua_pushboolean(L, 0);
		return 1;
	}

	addr1 = lua_touserdata(L, 1);
	addr2 = lua_touserdata(L, 2);

	if (addr1->family != addr2->family) {
		lua_pushboolean(L, 0);
		return 1;
	}

	if (addr1->family == AF_INET) {
		if ((addr1->addr.v4.ip.s_addr & addr2->addr.v4.mask.s_addr) ==
		    (addr2->addr.v4.ip.s_addr & addr1->addr.v4.mask.s_addr)) {
			lua_pushboolean(L, 1);
			return 1;
		}
	} else {
		int i;

		for (i = 0; i < 16; i += 4) {
			if ((read_u32(&addr1->addr.v6.ip.s6_addr[i]) &
			     read_u32(&addr2->addr.v6.mask.s6_addr[i])) !=
			    (read_u32(&addr2->addr.v6.ip.s6_addr[i]) &
			     read_u32(&addr1->addr.v6.mask.s6_addr[i])))
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

int hlua_patref_get_name(lua_State *L)
{
	struct hlua_patref *ref;


	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);

	lua_pushstring(L, ref->ptr->reference);
	return 1;
}

int hlua_patref_is_map(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);

	lua_pushboolean(L, !!(ref->ptr->flags & PAT_REF_MAP));
	return 1;
}

/* full-clear may require yielding between pruning
 * batches
 */
static int _hlua_patref_clear(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_patref *ref = hlua_checkudata(L, 1, class_patref_ref);
	unsigned int from = lua_tointeger(L, 2);
	unsigned int to = lua_tointeger(L, 3);
	int ret;

 loop:
	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);
	ret = pat_ref_purge_range(ref->ptr, from, to, 100);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);
	if (!ret) {
		hlua_yieldk(L, 0, 0, _hlua_patref_clear, TICK_ETERNITY, HLUA_CTRLYIELD); // continue
		/* never reached, unless if called from body/init state
		 * where yieldk is no-op, thus we can't do anything to prevent
		 * thread contention
		 */
		goto loop;
	}

	lua_pushboolean(L, 1);
	return 1; // end
}

int hlua_patref_commit(lua_State *L)
{
	struct hlua_patref *ref;
	int ret;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);

	if (!(ref->flags & HLUA_PATREF_FL_GEN))
		return hlua_error(L, "Nothing to do");

	ref->flags &= ~HLUA_PATREF_FL_GEN;
	ret = pat_ref_commit(ref->ptr, ref->curr_gen);

	if (ret)
		return hlua_error(L, "Commit failed");

	/* cleanup: prune previous generations: The range of generations
	 * that get trashed by a commit starts from the opposite of the
	 * current one and ends at the previous one.
         */
	lua_pushinteger(L, ref->curr_gen - ((~0U) >> 1)); // from
	lua_pushinteger(L, ref->curr_gen - 1); // to
	return _hlua_patref_clear(L, LUA_OK, 0);
}

int hlua_patref_giveup(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);

	if (!(ref->flags & HLUA_PATREF_FL_GEN)) {
		/* nothing to do */
		return 0;
	}

	lua_pushinteger(L, ref->curr_gen); // from
	lua_pushinteger(L, ref->curr_gen); // to
	_hlua_patref_clear(L, LUA_OK, 0);

	/* didn't make use of the generation ID, give it back to the API */
	pat_ref_giveup(ref->ptr, ref->curr_gen);

	return 0;
}

int hlua_patref_prepare(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);
	ref->curr_gen = pat_ref_newgen(ref->ptr);
	ref->flags |= HLUA_PATREF_FL_GEN;
	return 0;
}

int hlua_patref_purge(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	BUG_ON(!ref);

	lua_pushinteger(L, 0); // from
	lua_pushinteger(L, ~0); // to
	return _hlua_patref_clear(L, LUA_OK, 0);
}

int hlua_patref_add(lua_State *L)
{
	struct hlua_patref *ref;
	const char *key;
	const char *value = NULL;
	char *errmsg = NULL;
	int ret;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	BUG_ON(!ref);

	key = luaL_checkstring(L, 2);
	if (lua_gettop(L) == 3)
		value = luaL_checkstring(L, 3);

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);
	if ((ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(ref->ptr, ref->curr_gen))
		ret = !!pat_ref_load(ref->ptr, ref->curr_gen, key, value, -1, &errmsg);
	else
		ret = pat_ref_add(ref->ptr, key, value, &errmsg);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);


	if (!ret) {
		ret = hlua_error(L, errmsg);
		ha_free(&errmsg);
		return ret;
	}
	lua_pushboolean(L, 1);
	return 1;
}

/* re-entrant helper, expects table of string as second argument on the stack */
static int _hlua_patref_add_bulk(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_patref *ref = hlua_checkudata(L, 1, class_patref_ref);
	char *errmsg;
	unsigned int curr_gen;
	int count = 0;
	int ret;

	if ((ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(ref->ptr, ref->curr_gen))
		curr_gen = ref->curr_gen;
	else
		curr_gen = ref->ptr->curr_gen;

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);

	while (lua_next(L, 2) != 0) {
		const char *key;
		const char *value = NULL;

		/* check if we may do something to try to prevent thread contention,
		 * unless we run from body/init state where hlua_yieldk is no-op
		 */
		if (count > 100 && hlua_gethlua(L)) {
			/* let's yield and wait for being called again to continue where we left off */
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);
			hlua_yieldk(L, 0, 0, _hlua_patref_add_bulk, TICK_ETERNITY, HLUA_CTRLYIELD); // continue
			return 0; // not reached

		}

		if (ref->ptr->flags & PAT_REF_SMP) {
			/* key:val table */
			luaL_checktype(L, -2, LUA_TSTRING);
			key = lua_tostring(L, -2);
			luaL_checktype(L, -1, LUA_TSTRING);
			value = lua_tostring(L, -1);
		}
		else {
			/* key-only table, use value as key */
			luaL_checktype(L, -1, LUA_TSTRING);
			key = lua_tostring(L, -1);
		}

		if (!pat_ref_load(ref->ptr, curr_gen, key, value, -1, &errmsg)) {
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);
			ret = hlua_error(L, errmsg);
			ha_free(&errmsg);
			return ret;
		}


		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
		count += 1;
	}
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);
	lua_pushboolean(L, 1);
	return 1;
}
int hlua_patref_add_bulk(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	BUG_ON(!ref);

	/* table is in the stack at index 't' */
	lua_pushnil(L);  /* first key */
	return _hlua_patref_add_bulk(L, LUA_OK, 0);
}

int hlua_patref_del(lua_State *L)
{
	struct hlua_patref *ref;
	const char *key;
	int ret;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	BUG_ON(!ref);

	key = luaL_checkstring(L, 2);

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);
	if ((ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(ref->ptr, ref->curr_gen))
		ret = pat_ref_gen_delete(ref->ptr, ref->curr_gen, key);
	else
		ret = pat_ref_delete(ref->ptr, key);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);

	lua_pushboolean(L, !!ret);
	return 1;
}

int hlua_patref_set(lua_State *L)
{
	struct hlua_patref *ref;
	const char *key;
	const char *value;
	char *errmsg = NULL;
	unsigned int curr_gen;
	int force = 0;
	int ret;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	BUG_ON(!ref);

	key = luaL_checkstring(L, 2);
	value = luaL_checkstring(L, 3);

	if (lua_gettop(L) == 4)
		force = lua_toboolean(L, 4);

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);
	if ((ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(ref->ptr, ref->curr_gen))
		curr_gen = ref->curr_gen;
	else
		curr_gen = ref->ptr->curr_gen;

	if (force) {
		struct pat_ref_elt *elt;

		elt = pat_ref_gen_find_elt(ref->ptr, curr_gen, key);
		if (elt)
			ret = pat_ref_set_elt_duplicate(ref->ptr, elt, value, &errmsg);
		else
			ret = !!pat_ref_load(ref->ptr, curr_gen, key, value, -1, &errmsg);
	}
	else
		ret = pat_ref_gen_set(ref->ptr, curr_gen, key, value, &errmsg);

	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);

	if (!ret) {
		ret = hlua_error(L, errmsg);
		ha_free(&errmsg);
		return ret;
	}
	lua_pushboolean(L, 1);
	return 1;
}

/* hlua_event_sub wrapper for per-patref subscription:
 *
 * hlua_event_sub() is called with ref->ptr->e_subs subscription list and
 * lua arguments are passed as-is (skipping the first argument which
 * is the hlua_patref)
 */
int hlua_patref_event_sub(lua_State *L)
{
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	BUG_ON(!ref);

	/* remove first argument from the stack (hlua_patref) */
	lua_remove(L, 1);

	/* try to subscribe within patref's subscription list */
	return hlua_event_sub(L, &ref->ptr->e_subs);
}

void hlua_fcn_new_patref(lua_State *L, struct pat_ref *ref)
{
	struct hlua_patref *_ref;

	lua_newtable(L);

	/* Pop a class patref metatable and affect it to the userdata
	 * (if provided)
	 */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_patref_ref);
	lua_setmetatable(L, -2);

	if (ref) {
		/* allocate hlua_patref wrapper and store it in the metatable */
		_ref = malloc(sizeof(*_ref));
		if (!_ref)
			luaL_error(L, "Lua out of memory error.");
		_ref->ptr = ref;
		_ref->curr_gen = 0;
		_ref->flags = HLUA_PATREF_FL_NONE;
		lua_pushlightuserdata(L, _ref);
		lua_rawseti(L, -2, 0);
	}

	/* set public methods */
	hlua_class_function(L, "get_name", hlua_patref_get_name);
	hlua_class_function(L, "is_map", hlua_patref_is_map);
	hlua_class_function(L, "prepare", hlua_patref_prepare);
	hlua_class_function(L, "commit", hlua_patref_commit);
	hlua_class_function(L, "giveup", hlua_patref_giveup);
	hlua_class_function(L, "purge", hlua_patref_purge);
	hlua_class_function(L, "add", hlua_patref_add);
	hlua_class_function(L, "add_bulk", hlua_patref_add_bulk);
	hlua_class_function(L, "del", hlua_patref_del);
	hlua_class_function(L, "set", hlua_patref_set);
	hlua_class_function(L, "event_sub", hlua_patref_event_sub);
}

int hlua_patref_gc(lua_State *L)
{
	struct hlua_patref *ref = hlua_checkudata(L, 1, class_patref_ref);

	free(ref);
	return 0;
}

int hlua_listable_patref_newindex(lua_State *L) {
	/* not yet supported */
	return 0;
}

/* first arg is the pat_ref
 * second arg is the required index, in case of duplicate, only the
 * first matching entry is returned.
 */
int hlua_listable_patref_index(lua_State *L)
{
	struct hlua_patref *ref;
	const char *key;
	struct pat_ref_elt *elt;

	ref = hlua_checkudata(L, 1, class_patref_ref);
	key = luaL_checkstring(L, 2);

	/* Perform pat ref element lookup by key */
	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ref->ptr->lock);
	if ((ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(ref->ptr, ref->curr_gen))
		elt = pat_ref_gen_find_elt(ref->ptr, ref->curr_gen, key);
	else
		elt = pat_ref_find_elt(ref->ptr, key);
	if (elt == NULL) {
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);
		lua_pushnil(L);
		return 1;
	}

	if (elt->sample)
		lua_pushstring(L, elt->sample);
	else
		lua_pushboolean(L, 1); // acl: just push true to tell that the key exists
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ref->ptr->lock);

	return 1;
}

static int _hlua_listable_patref_pairs_iterator(lua_State *L, int status, lua_KContext ctx)
{
	int context_index;
	struct hlua_patref_iterator_context *hctx;
	struct pat_ref_elt *elt;
	int cnt = 0;
	unsigned int curr_gen;

	context_index = lua_upvalueindex(1);
	hctx = lua_touserdata(L, context_index);

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &hctx->ref->ptr->lock);

	if ((hctx->ref->flags & HLUA_PATREF_FL_GEN) &&
	    pat_ref_may_commit(hctx->ref->ptr, hctx->ref->curr_gen))
		curr_gen = hctx->ref->curr_gen;
	else
		curr_gen = hctx->ref->ptr->curr_gen;

	if (LIST_ISEMPTY(&hctx->bref.users)) {
		/* first iteration */
		hctx->bref.ref = hctx->ref->ptr->head.n;
	}
	else
		LIST_DEL_INIT(&hctx->bref.users); // drop back ref from previous iteration

 next:
	/* reached end of list? */
	if (hctx->bref.ref == &hctx->ref->ptr->head) {
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &hctx->ref->ptr->lock);
		lua_pushnil(L);
		return 1;
	}

	elt = LIST_ELEM(hctx->bref.ref, struct pat_ref_elt *, list);

	if (elt->gen_id != curr_gen) {
		/* check if we may do something to try to prevent thread contention,
		 * unless we run from body/init state where hlua_yieldk is no-op
		 */
		if (cnt > 10000 && hlua_gethlua(L)) {
			/* let's yield and wait for being called again to continue where we left off */
			LIST_APPEND(&elt->back_refs, &hctx->bref.users);
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &hctx->ref->ptr->lock);
			hlua_yieldk(L, 0, 0, _hlua_listable_patref_pairs_iterator, TICK_ETERNITY, HLUA_CTRLYIELD); // continue
			return 0; // not reached
		}

		hctx->bref.ref = elt->list.n;
		cnt++;
		goto next;
	}

	LIST_APPEND(&elt->back_refs, &hctx->bref.users);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &hctx->ref->ptr->lock);

	hctx->bref.ref = elt->list.n;

	lua_pushstring(L, elt->pattern);
	if (elt->sample)
		lua_pushstring(L, elt->sample);
	else
		return 1;
	return 2;

}
/* iterator must return key as string and value as patref
 * element value (as string), if we reach end of list, it
 * returns nil. The context knows the last returned patref's
 * value. if the context contains patref_elem == NULL, we
 * start enumeration. We use pat_ref element iterator logic
 * to iterate through the list.
 */
int hlua_listable_patref_pairs_iterator(lua_State *L)
{
	return _hlua_listable_patref_pairs_iterator(L, LUA_OK, 0);
}

/* init the iterator context, return iterator function
 * with context as closure. The only argument is a
 * patref list object.
 */
int hlua_listable_patref_pairs(lua_State *L)
{
	struct hlua_patref_iterator_context *ctx;
	struct hlua_patref *ref;

	ref = hlua_checkudata(L, 1, class_patref_ref);

	ctx = lua_newuserdata(L, sizeof(*ctx));
	ctx->ref = ref;
	LIST_INIT(&ctx->bref.users);

	lua_pushcclosure(L, hlua_listable_patref_pairs_iterator, 1);
	return 1;
}

void hlua_fcn_reg_core_fcn(lua_State *L)
{
	hlua_concat_init(L);
	hlua_queue_init(L);

	hlua_class_function(L, "now", hlua_now);
	hlua_class_function(L, "http_date", hlua_http_date);
	hlua_class_function(L, "imf_date", hlua_imf_date);
	hlua_class_function(L, "rfc850_date", hlua_rfc850_date);
	hlua_class_function(L, "asctime_date", hlua_asctime_date);
	hlua_class_function(L, "concat", hlua_concat_new);
	hlua_class_function(L, "queue", hlua_queue_new);
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

	/* Create event_sub object. */
	lua_newtable(L);
	hlua_class_function(L, "__gc", hlua_event_sub_gc);
	class_event_sub_ref = hlua_register_metatable(L, CLASS_EVENT_SUB);

	/* Create patref object. */
	lua_newtable(L);
	hlua_class_function(L, "__index", hlua_listable_patref_index);
	hlua_class_function(L, "__newindex", hlua_listable_patref_newindex);
	hlua_class_function(L, "__pairs", hlua_listable_patref_pairs);
	hlua_class_function(L, "__gc", hlua_patref_gc);
	class_patref_ref = hlua_register_metatable(L, CLASS_PATREF);

	/* Create server object. */
	lua_newtable(L);
	hlua_class_function(L, "__gc", hlua_server_gc);
	hlua_class_function(L, "__index", hlua_server_index);
	class_server_ref = hlua_register_metatable(L, CLASS_SERVER);

	/* Create proxy object. */
	lua_newtable(L);
	hlua_class_function(L, "__index", hlua_proxy_index);
	class_proxy_ref = hlua_register_metatable(L, CLASS_PROXY);

	/* list of proxy objects. Instead of having a static array
	 * of proxies, we use special metamethods that rely on internal
	 * proxies list so that the array is resolved at runtime.
	 *
	 * To emulate the same behavior than Lua array, we implement some
	 * metatable functions:
	 *  - __newindex : prevent the insertion of a new item in the array
	 *  - __index : find a proxy in the list using "name" index
	 *  - __pairs : iterate through available proxies in the list
	 */
	lua_newtable(L);
	hlua_class_function(L, "__index", hlua_listable_proxies_index);
	hlua_class_function(L, "__newindex", hlua_listable_proxies_newindex);
	hlua_class_function(L, "__pairs", hlua_listable_proxies_pairs);
	class_proxy_list_ref = hlua_register_metatable(L, CLASS_PROXY_LIST);

	/* Create proxies entry. */
	lua_pushstring(L, "proxies");
	hlua_listable_proxies(L, PR_CAP_LISTEN);
	lua_settable(L, -3);

	/* Create frontends entry. */
	lua_pushstring(L, "frontends");
	hlua_listable_proxies(L, PR_CAP_FE);
	lua_settable(L, -3);

	/* Create backends entry. */
	lua_pushstring(L, "backends");
	hlua_listable_proxies(L, PR_CAP_BE);
	lua_settable(L, -3);

	/* list of server. This object is similar to
	 * CLASS_PROXY_LIST
	 */
	lua_newtable(L);
	hlua_class_function(L, "__index", hlua_listable_servers_index);
	hlua_class_function(L, "__newindex", hlua_listable_servers_newindex);
	hlua_class_function(L, "__pairs", hlua_listable_servers_pairs);
	class_server_list_ref = hlua_register_metatable(L, CLASS_SERVER_LIST);
}
