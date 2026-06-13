/*
 * include/haproxy/hlua.h
 * Lua core management functions
 *
 * Copyright (C) 2015-2016 Thierry Fournier <tfournier@arpalert.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_HLUA_H
#define _HAPROXY_HLUA_H

#include <haproxy/hlua-t.h>

#ifdef USE_LUA

/* Lua uses longjmp to perform yield or throwing errors. This
 * macro is used only for identifying the function that can
 * not return because a longjmp is executed.
 *   __LJMP marks a prototype of hlua file that can use longjmp.
 *   WILL_LJMP() marks an lua function that will use longjmp.
 *   MAY_LJMP() marks an lua function that may use longjmp.
 */
#define __LJMP
#define WILL_LJMP(func) do { func; my_unreachable(); } while(0)
#define MAY_LJMP(func) func

/* The following macros are used to set flags. */
#define HLUA_SET_RUN(__hlua)         do {(__hlua)->flags |= HLUA_RUN;} while(0)
#define HLUA_CLR_RUN(__hlua)         do {(__hlua)->flags &= ~HLUA_RUN;} while(0)
#define HLUA_IS_RUNNING(__hlua)      ((__hlua)->flags & HLUA_RUN)
#define HLUA_SET_BUSY(__hlua)        do {(__hlua)->flags |= HLUA_BUSY;} while(0)
#define HLUA_CLR_BUSY(__hlua)        do {(__hlua)->flags &= ~HLUA_BUSY;} while(0)
#define HLUA_IS_BUSY(__hlua)         ((__hlua)->flags & HLUA_BUSY)
#define HLUA_SET_CTRLYIELD(__hlua)   do {(__hlua)->flags |= HLUA_CTRLYIELD;} while(0)
#define HLUA_CLR_CTRLYIELD(__hlua)   do {(__hlua)->flags &= ~HLUA_CTRLYIELD;} while(0)
#define HLUA_IS_CTRLYIELDING(__hlua) ((__hlua)->flags & HLUA_CTRLYIELD)
#define HLUA_SET_WAKERESWR(__hlua)   do {(__hlua)->flags |= HLUA_WAKERESWR;} while(0)
#define HLUA_CLR_WAKERESWR(__hlua)   do {(__hlua)->flags &= ~HLUA_WAKERESWR;} while(0)
#define HLUA_IS_WAKERESWR(__hlua)    ((__hlua)->flags & HLUA_WAKERESWR)
#define HLUA_SET_WAKEREQWR(__hlua)   do {(__hlua)->flags |= HLUA_WAKEREQWR;} while(0)
#define HLUA_CLR_WAKEREQWR(__hlua)   do {(__hlua)->flags &= ~HLUA_WAKEREQWR;} while(0)
#define HLUA_IS_WAKEREQWR(__hlua)    ((__hlua)->flags & HLUA_WAKEREQWR)
#define HLUA_CLR_NOYIELD(__hlua)     do {(__hlua)->flags &= ~HLUA_NOYIELD;} while(0)
#define HLUA_SET_NOYIELD(__hlua)     do {(__hlua)->flags |= HLUA_NOYIELD;} while(0)
#define HLUA_CANT_YIELD(__hlua)      ((__hlua)->flags & HLUA_NOYIELD)


#define HLUA_INIT(__hlua) do { (__hlua)->T = 0; } while(0)

/* Lua HAProxy integration functions. */
void hlua_yield_asap(lua_State *L);
void hap_register_hlua_state_init(int (*fct)(lua_State *L, char **errmsg));

/* simplified way to register a lua_State init callback from any file */
#define REGISTER_HLUA_STATE_INIT(fct) \
	INITCALL1(STG_REGISTER, hap_register_hlua_state_init, (fct))
const char *hlua_traceback(lua_State *L, const char* sep);
void hlua_ctx_destroy(struct hlua *lua);
void hlua_init();
int hlua_post_init();
void hlua_applet_tcp_fct(struct appctx *ctx);
void hlua_applet_http_fct(struct appctx *ctx);
int hlua_event_sub(lua_State *L, event_hdl_sub_list *sub_list);
struct task *hlua_process_task(struct task *task, void *context, unsigned int state);
const char *hlua_show_current_location(const char *pfx);
int hlua_ref(lua_State *L);
void hlua_pushref(lua_State *L, int ref);
void hlua_unref(lua_State *L, int ref);
struct hlua *hlua_gethlua(lua_State *L);
void hlua_yieldk(lua_State *L, int nresults, lua_KContext ctx, lua_KFunction k, int timeout, unsigned int flags);
int hlua_pusherror(lua_State *L, const char *fmt, ...);

__LJMP static inline void hlua_check_args(lua_State *L, int nb, char *fcn)
{
	if (lua_gettop(L) == nb)
		return;
	WILL_LJMP(luaL_error(L, "'%s' needs %d arguments", fcn, nb));
}
#define check_args hlua_check_args

#else /* USE_LUA */

/************************ For use when Lua is disabled ********************/

#define HLUA_IS_RUNNING(__hlua) 0

#define HLUA_INIT(__hlua)

/* Empty function for compilation without Lua. */
static inline void hlua_init() { }
static inline int hlua_post_init() { return 1; }
static inline void hlua_ctx_destroy(struct hlua *lua) { }
static inline const char *hlua_show_current_location(const char *pfx) { return NULL; }

#endif /* USE_LUA */

#endif /* _HAPROXY_HLUA_H */
